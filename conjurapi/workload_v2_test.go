package conjurapi

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestClient(serverURL string) Client {
	return Client{
		config: Config{
			ApplianceURL: serverURL,
			Account:      "myTestAccount",
		},
	}
}

// newWorkloadMockServer returns a fully-authenticated SaaS-mode Client
// pointing at a mock server, so the workload wrapper methods can be exercised
// end to end rather than only through their *Request builders.
func newWorkloadMockServer(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	return newAuthenticatedMockServer(t, EnvironmentSaaS, handler)
}

func validWorkload() Workload {
	return Workload{
		Name:   "testWorkload",
		Branch: "data",
		AuthnDescriptors: []AuthnDescriptor{
			{Type: "authn-jwt", ServiceID: "jwt_service"},
		},
	}
}

func TestCreateWorkloadRequest_MinimalSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Error wrong http method used")
		}
		if r.URL.Path != "/workloads" {
			t.Errorf("Error Url is not proper: %s, should be: %s", r.URL.Path, "localhost/workloads")
		}
		body, _ := io.ReadAll(r.Body)
		var workload Workload
		if err := json.Unmarshal(body, &workload); err != nil {
			t.Errorf("Unmarshal error: %s body=%s", err, string(body))
		}
		if workload.Name != "testWorkload" {
			t.Errorf("Unexpected name: %s", workload.Name)
		}
		if workload.Branch != "data" {
			t.Errorf("Unexpected branch: %s", workload.Branch)
		}
		if workload.Type != "other" {
			t.Errorf("Unexpected type: %s", workload.Type)
		}
		if len(workload.AuthnDescriptors) != 1 || workload.AuthnDescriptors[0].Type != "authn-jwt" || workload.AuthnDescriptors[0].ServiceID != "jwt_service" {
			t.Errorf("Unexpected authn_descriptors: %+v", workload.AuthnDescriptors)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	c := newTestClient(ts.URL)

	req, err := c.V2().CreateWorkloadRequest(validWorkload())
	if err != nil {
		t.Errorf("Error Test failed %s", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("Request error: %s", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected 201, got %d", resp.StatusCode)
	}
}

// TestCreateWorkloadRequest_OmitsServerSuppliedFields pins the create body
// against the server-supplied attributes Workload carries for GetWorkload's
// benefit (authentication_source, identity_source, created_at). They are
// omitempty, so a workload a caller builds must still marshal to exactly the
// body it did before those fields existed.
func TestCreateWorkloadRequest_OmitsServerSuppliedFields(t *testing.T) {
	c := newTestClient("http://conjur.test")

	req, err := c.V2().CreateWorkloadRequest(validWorkload())
	require.NoError(t, err)

	body, _ := io.ReadAll(req.Body)
	assert.JSONEq(t, `{
		"name": "testWorkload",
		"branch": "data",
		"type": "other",
		"authn_descriptors": [{"type":"authn-jwt","service_id":"jwt_service"}]
	}`, string(body))
}

func TestCreateWorkloadRequest_JenkinsJWTWithAnnotationsSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var workload Workload
		if err := json.Unmarshal(body, &workload); err != nil {
			t.Errorf("Unmarshal error: %s body=%s", err, string(body))
		}
		if workload.Name != "jenkins-ci-workload" {
			t.Errorf("Unexpected name: %s", workload.Name)
		}
		if workload.Type != "Jenkins" {
			t.Errorf("Unexpected type: %s", workload.Type)
		}
		if workload.Owner == nil || workload.Owner.Kind != "user" || workload.Owner.Id != "e2e_test@cyberark.com" {
			t.Errorf("Unexpected owner: %+v", workload.Owner)
		}
		expectedAnn := map[string]string{"my_devops_team": "CI_CD"}
		if !reflect.DeepEqual(workload.Annotations, expectedAnn) {
			t.Errorf("Unexpected annotations. got=%s want=%s", workload.Annotations, expectedAnn)
		}
		if len(workload.AuthnDescriptors) != 1 {
			t.Errorf("Expected 1 authn descriptor, got %d", len(workload.AuthnDescriptors))
		}
		ad := workload.AuthnDescriptors[0]
		if ad.Type != "authn-jwt" || ad.ServiceID != "jwt_service" {
			t.Errorf("Unexpected authn descriptor: %+v", ad)
		}
		if ad.Data == nil || ad.Data.Claims["jenkins_task_noun"] != "Build" ||
			ad.Data.Claims["jenkins_pronoun"] != "CC" ||
			ad.Data.Claims["jenkins_parent_full_name"] != "/main" {
			t.Errorf("Unexpected claims: %+v", ad.Data)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	c := newTestClient(ts.URL)
	workloadData := Workload{
		Name:   "jenkins-ci-workload",
		Branch: "data",
		Type:   "Jenkins",
		Owner: &Owner{
			Kind: "user",
			Id:   "e2e_test@cyberark.com",
		},
		Annotations: map[string]string{
			"my_devops_team": "CI_CD",
		},
		AuthnDescriptors: []AuthnDescriptor{
			{
				Type:      "authn-jwt",
				ServiceID: "jwt_service",
				Data: &AuthnDescriptorData{
					Claims: map[string]string{
						"jenkins_task_noun":        "Build",
						"jenkins_pronoun":          "CC",
						"jenkins_parent_full_name": "/main",
					},
				},
			},
		},
	}

	req, err := c.V2().CreateWorkloadRequest(workloadData)
	if err != nil {
		t.Errorf("Error Test failed %s", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("Request error: %s", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected 201, got %d", resp.StatusCode)
	}
}

func TestCreateWorkloadRequest_ApiKeyRestrictedIPsSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var workload Workload
		if err := json.Unmarshal(body, &workload); err != nil {
			t.Errorf("Unmarshal error: %s body=%s", err, string(body))
		}
		if workload.Name != "api-key-client" {
			t.Errorf("Unexpected name: %s", workload.Name)
		}
		if workload.Branch != "data/us-east1/test" {
			t.Errorf("Unexpected branch: %s", workload.Branch)
		}
		if len(workload.RestrictedTo) != 2 || workload.RestrictedTo[0] != "1.2.4.5" || workload.RestrictedTo[1] != "10.20.30.10" {
			t.Errorf("Unexpected restricted_to: %s", workload.RestrictedTo)
		}
		if len(workload.AuthnDescriptors) != 1 || workload.AuthnDescriptors[0].Type != "authn_api_key" {
			t.Errorf("Unexpected authn_descriptors: %+v", workload.AuthnDescriptors)
		}
		if workload.Owner == nil || workload.Owner.Id != "e2e_test@cyberark.com" {
			t.Errorf("Unexpected owner: %+v", workload.Owner)
		}
		if workload.Type != "other" {
			t.Errorf("Unexpected type: %s", workload.Type)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	c := newTestClient(ts.URL)
	workloadData := Workload{
		Name:   "api-key-client",
		Branch: "data/us-east1/test",
		Owner: &Owner{
			Kind: "user",
			Id:   "e2e_test@cyberark.com",
		},
		RestrictedTo: []string{"1.2.4.5", "10.20.30.10"},
		AuthnDescriptors: []AuthnDescriptor{
			{Type: "authn_api_key"},
		},
	}

	req, err := c.V2().CreateWorkloadRequest(workloadData)
	if err != nil {
		t.Errorf("Error Test failed %s", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("Request error: %s", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected 201, got %d", resp.StatusCode)
	}
}

func TestCreateWorkloadRequest_MissingNameValidationError422(t *testing.T) {
	c := newTestClient("http://conjur.test")

	workload := validWorkload()
	workload.Name = ""

	req, err := c.V2().CreateWorkloadRequest(workload)
	if err == nil {
		t.Errorf("Expected error for missing name, got nil (request=%v)", req)
	}
	if !strings.Contains(err.Error(), "Workload Name") {
		t.Errorf("Expected error to mention Workload Name, got %s", err)
	}
}

func TestCreateWorkloadRequest_MissingBranchValidationError422(t *testing.T) {
	c := newTestClient("http://conjur.test")

	workload := validWorkload()
	workload.Branch = ""

	req, err := c.V2().CreateWorkloadRequest(workload)
	if err == nil {
		t.Errorf("Expected error for missing branch, got nil (request=%v)", req)
	}
	if !strings.Contains(err.Error(), "Workload Branch") {
		t.Errorf("Expected error to mention Workload Branch, got %s", err)
	}
}

// TestCreateWorkloadRequest_AuthnDescriptorValidationErrors covers the
// authn_descriptors checks that live in CreateWorkloadRequest itself (as
// opposed to Workload.Validate): at least one descriptor is required, and
// every descriptor must carry a type.
func TestCreateWorkloadRequest_AuthnDescriptorValidationErrors(t *testing.T) {
	c := newTestClient("http://conjur.test")

	cases := []struct {
		name        string
		mutate      func(w *Workload)
		wantMessage string
	}{
		{
			name:        "no descriptors",
			mutate:      func(w *Workload) { w.AuthnDescriptors = nil },
			wantMessage: "at least one authenticator",
		},
		{
			name:        "descriptor missing type",
			mutate:      func(w *Workload) { w.AuthnDescriptors[0].Type = "" },
			wantMessage: "authn_descriptors[0] missing type",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			workload := validWorkload()
			tc.mutate(&workload)

			_, err := c.V2().CreateWorkloadRequest(workload)
			if err == nil {
				t.Fatalf("Expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantMessage) {
				t.Errorf("Expected error to mention %q, got %s", tc.wantMessage, err)
			}
		})
	}
}

func TestCreateWorkloadRequest_DuplicateWorkload409(t *testing.T) {
	created := map[string]bool{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var workload Workload
		_ = json.Unmarshal(body, &workload)
		if created[workload.Name] {
			w.WriteHeader(http.StatusConflict)
			return
		}
		created[workload.Name] = true
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	c := newTestClient(ts.URL)
	workload := validWorkload()

	// First create (201)
	req1, err := c.V2().CreateWorkloadRequest(workload)
	if err != nil {
		t.Errorf("Error Test failed %s", err)
	}
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Errorf("Request failed: %s", err)
	}
	if resp1.StatusCode != http.StatusCreated {
		t.Errorf("expected 201, got %d", resp1.StatusCode)
	}

	// Second create (409)
	req2, err := c.V2().CreateWorkloadRequest(workload)
	if err != nil {
		t.Errorf("Error Test failed %s", err)
	}
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Errorf("Request failed: %s", err)
	}
	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("Expected 409, got %d", resp2.StatusCode)
	}
}

func TestCreateWorkloadRequest_MalformedIPs422(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var workload Workload
		_ = json.Unmarshal(body, &workload)
		for _, ip := range workload.RestrictedTo {
			parsed := net.ParseIP(ip)
			if parsed == nil {
				w.WriteHeader(http.StatusUnprocessableEntity)
				return
			}
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	c := newTestClient(ts.URL)

	workload := validWorkload()
	workload.RestrictedTo = []string{"1.2.3.999", "10.0.0.1"}

	req, err := c.V2().CreateWorkloadRequest(workload)
	if err != nil {
		t.Errorf("Error Test failed %s", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("Request failed: %s", err)
	}
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("Expected 422, got %d", resp.StatusCode)
	}
}

func TestCreateWorkloadRequest_ExpectedContentType(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	c := newTestClient(ts.URL)
	req, err := c.V2().CreateWorkloadRequest(validWorkload())
	if err != nil {
		t.Errorf("Error Test failed %s", err)
	}

	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))

	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.NotEqual(t, http.StatusBadRequest, resp.StatusCode)
}

func TestCreateWorkloadRequest_Unauthorized401(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Authorization"), "token") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	c := newTestClient(ts.URL)
	req, err := c.V2().CreateWorkloadRequest(validWorkload())
	if err != nil {
		t.Errorf("Error Test failed %s", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("Request failed: %s", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", resp.StatusCode)
	}
}

func TestCreateWorkloadRequest_Forbidden403(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var workload Workload
		_ = json.Unmarshal(body, &workload)
		if workload.Branch == "forbidden/branch" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	c := newTestClient(ts.URL)
	workload := validWorkload()
	workload.Branch = "forbidden/branch"

	req, err := c.V2().CreateWorkloadRequest(workload)
	if err != nil {
		t.Errorf("Error Test failed %s", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("Request failed: %s", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", resp.StatusCode)
	}
}

// workloadRequestBuilders is every request builder that takes a workload
// identifier, so identifier handling can be asserted uniformly across them.
func workloadRequestBuilders(c Client) map[string]func(string) (*http.Request, error) {
	return map[string]func(string) (*http.Request, error){
		"DeleteWorkloadRequest": func(id string) (*http.Request, error) {
			return c.V2().DeleteWorkloadRequest(id)
		},
		"GetWorkloadRequest": func(id string) (*http.Request, error) {
			return c.V2().GetWorkloadRequest(id)
		},
		"UpdateWorkloadRequest": func(id string) (*http.Request, error) {
			return c.V2().UpdateWorkloadRequest(id, WorkloadFields{})
		},
	}
}

// TestWorkloadRequests_RejectInvalidIdentifiers asserts that every builder
// taking a workload identifier rejects one that is empty, "." or "..".
// url.PathEscape leaves all three untouched, so they would reach path.Join
// inside makeRouterURL, which resolves them - "." addressing the /workloads
// collection instead of a workload, and ".." escaping the prefix entirely.
func TestWorkloadRequests_RejectInvalidIdentifiers(t *testing.T) {
	c := newTestClient("http://conjur.test")

	identifiers := []string{"", ".", ".."}

	for name, build := range workloadRequestBuilders(c) {
		t.Run(name, func(t *testing.T) {
			for _, identifier := range identifiers {
				if _, err := build(identifier); err == nil {
					t.Errorf("%s(%q): expected an error, got none", name, identifier)
				}
			}
		})
	}
}

// TestWorkloadRequests_FlattenTraversalIdentifiers asserts that an identifier
// shaped like path navigation is escaped into a single opaque segment rather
// than rejected or resolved. Because the identifier is escaped whole, every "/"
// in it becomes %2F, so path.Join sees no separators and has nothing to collapse
// or resolve - the traversal is inert without the client having to police it.
// Whether such an identifier names a real workload is the server's call.
func TestWorkloadRequests_FlattenTraversalIdentifiers(t *testing.T) {
	c := newTestClient("http://conjur.test")

	// Each identifier must stay wholly inside the /workloads/ prefix, as one
	// segment, with no unescaped "/" beyond the one the prefix ends with.
	identifiers := []string{"/", "data//w", "data/", "/data", "data/./apps", "foo/../../secrets/bar"}

	for name, build := range workloadRequestBuilders(c) {
		t.Run(name, func(t *testing.T) {
			for _, identifier := range identifiers {
				req, err := build(identifier)
				if err != nil {
					t.Errorf("%s(%q): unexpected error: %s", name, identifier, err)
					continue
				}
				want := "/workloads/" + url.PathEscape(identifier)
				got := req.URL.EscapedPath()
				// UpdateAuthnDescriptorRequest appends its own real segments.
				if !strings.HasPrefix(got, want) {
					t.Errorf("%s(%q): escaped path %q does not start with %q",
						name, identifier, got, want)
				}
				if strings.Contains(strings.TrimPrefix(got, "/workloads/"+url.PathEscape(identifier)), "//") {
					t.Errorf("%s(%q): escaped path %q contains an empty segment",
						name, identifier, got)
				}
			}
		})
	}
}

func TestDeleteWorkloadRequest_Endpoint(t *testing.T) {
	c := newTestClient("http://conjur.test")

	req, err := c.V2().DeleteWorkloadRequest("data/apps/my-workload")
	if err != nil {
		t.Errorf("Error Test failed %s", err)
	}
	if req.Method != http.MethodDelete {
		t.Errorf("Expected DELETE, got %s", req.Method)
	}
	// Workloads created via POST /workloads are deleted via DELETE /workloads/<id>,
	// not /hosts/<id>. The identifier goes on the wire as one escaped segment,
	// which the server decodes back to the same branch path.
	if req.URL.EscapedPath() != "/workloads/data%2Fapps%2Fmy-workload" {
		t.Errorf("Unexpected escaped path: %s, want /workloads/data%%2Fapps%%2Fmy-workload", req.URL.EscapedPath())
	}
	if req.URL.Path != "/workloads/data/apps/my-workload" {
		t.Errorf("Unexpected path: %s, want /workloads/data/apps/my-workload", req.URL.Path)
	}
}

// TestDeleteWorkloadRequest_EscapesSpecialCharacters asserts that characters
// requiring URL escaping (space, '?', '#') are escaped rather than passed
// through raw and misparsed as query/fragment delimiters by http.NewRequest.
func TestDeleteWorkloadRequest_EscapesSpecialCharacters(t *testing.T) {
	c := newTestClient("http://conjur.test")

	req, err := c.V2().DeleteWorkloadRequest("data/apps/my workload?#")
	if err != nil {
		t.Errorf("Error Test failed %s", err)
	}
	if req.URL.Path != "/workloads/data/apps/my workload?#" {
		t.Errorf("Unexpected path: %s, want /workloads/data/apps/my workload?#", req.URL.Path)
	}
	if req.URL.RawQuery != "" {
		t.Errorf("Expected no query string, got %q", req.URL.RawQuery)
	}
	if req.URL.Fragment != "" {
		t.Errorf("Expected no fragment, got %q", req.URL.Fragment)
	}
}

// TestGetWorkloadRequest_Endpoint asserts that a branch-path identifier travels
// as one escaped segment (%2F for each "/"), which the server decodes back into
// the branch path. Asserting req.URL.Path alone cannot tell the two encodings
// apart, since %2F decodes to "/" - hence the EscapedPath assertion.
func TestGetWorkloadRequest_Endpoint(t *testing.T) {
	c := newTestClient("http://conjur.test")

	req, err := c.V2().GetWorkloadRequest("data/apps/my-workload")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if req.Method != http.MethodGet {
		t.Errorf("Expected GET, got %s", req.Method)
	}
	if req.URL.EscapedPath() != "/workloads/data%2Fapps%2Fmy-workload" {
		t.Errorf("Unexpected escaped path: %s, want /workloads/data%%2Fapps%%2Fmy-workload", req.URL.EscapedPath())
	}
	if req.URL.Path != "/workloads/data/apps/my-workload" {
		t.Errorf("Unexpected path: %s, want /workloads/data/apps/my-workload", req.URL.Path)
	}
	if req.URL.RawQuery != "" {
		t.Errorf("Expected no query string, got %q", req.URL.RawQuery)
	}
}

// TestGetWorkloadRequest_EscapesSpecialCharacters asserts the same escaping
// DeleteWorkloadRequest does: a space (and '?', '#') is escaped rather than
// passed through raw and misparsed as a query/fragment delimiter by
// http.NewRequest.
func TestGetWorkloadRequest_EscapesSpecialCharacters(t *testing.T) {
	c := newTestClient("http://conjur.test")

	req, err := c.V2().GetWorkloadRequest("data/apps/my workload?#")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if req.URL.Path != "/workloads/data/apps/my workload?#" {
		t.Errorf("Unexpected path: %s, want /workloads/data/apps/my workload?#", req.URL.Path)
	}
	if req.URL.EscapedPath() != "/workloads/data%2Fapps%2Fmy%20workload%3F%23" {
		t.Errorf("Unexpected escaped path: %s", req.URL.EscapedPath())
	}
	if req.URL.RawQuery != "" {
		t.Errorf("Expected no query string, got %q", req.URL.RawQuery)
	}
	if req.URL.Fragment != "" {
		t.Errorf("Expected no fragment, got %q", req.URL.Fragment)
	}
}

func TestDeleteWorkloadRequest_Unauthorized401(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Authorization"), "token") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	c := newTestClient(ts.URL)
	req, err := c.V2().DeleteWorkloadRequest("testWorkload")
	if err != nil {
		t.Errorf("Error Test failed %s", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("Request error: %s", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", resp.StatusCode)
	}
}

// TestNewWorkloadEndpoints_AcceptHeader centralizes Accept header validation
// for all workload v2 routes, so header changes only need updating here.
func TestNewWorkloadEndpoints_AcceptHeader(t *testing.T) {
	c := newTestClient("http://conjur.test")
	identifier := "data/us-east1/test/new-client"

	cases := []struct {
		name  string
		build func() (*http.Request, error)
	}{
		{"CreateWorkloadRequest", func() (*http.Request, error) {
			return c.V2().CreateWorkloadRequest(validWorkload())
		}},
		{"DeleteWorkloadRequest", func() (*http.Request, error) {
			return c.V2().DeleteWorkloadRequest(identifier)
		}},
		{"GetWorkloadRequest", func() (*http.Request, error) {
			return c.V2().GetWorkloadRequest(identifier)
		}},
		{"UpdateWorkloadRequest", func() (*http.Request, error) {
			return c.V2().UpdateWorkloadRequest(identifier, WorkloadFields{Annotations: map[string]string{"a": "b"}})
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := tc.build()
			if err != nil {
				t.Fatalf("%s: unexpected error: %s", tc.name, err)
			}
			got := req.Header.Get(v2APIOutgoingHeaderID)
			if got != v2APIHeader {
				t.Errorf("%s: Accept header = %q, want %q", tc.name, got, v2APIHeader)
			}
		})
	}
}

// TestUpdateWorkloadRequest_EndpointAndBody asserts the PATCH endpoint and
// pins Annotations-only marshaling of WorkloadFields.
func TestUpdateWorkloadRequest_EndpointAndBody(t *testing.T) {
	c := newTestClient("http://conjur.test")

	update := WorkloadFields{
		Annotations: map[string]string{"team": "devops-updated"},
	}
	req, err := c.V2().UpdateWorkloadRequest("data/us-east1/test/new-client", update)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if req.Method != http.MethodPatch {
		t.Errorf("Expected PATCH, got %s", req.Method)
	}
	if req.URL.Path != "/workloads/data/us-east1/test/new-client" {
		t.Errorf("Unexpected path: %s", req.URL.Path)
	}
	body, _ := io.ReadAll(req.Body)
	assert.JSONEq(t, `{"annotations":{"team":"devops-updated"}}`, string(body))
}

// TestUpdateWorkloadRequest_AuthnDescriptorsBody asserts that PATCHing
// authn_descriptors sends the whole array as-is:
// the caller is expected to resend the full desired list,
// and the server replaces the array wholesale rather than
// merging per element.
func TestUpdateWorkloadRequest_AuthnDescriptorsBody(t *testing.T) {
	c := newTestClient("http://conjur.test")

	req, err := c.V2().UpdateWorkloadRequest("data/w", WorkloadFields{
		AuthnDescriptors: []AuthnDescriptor{{Type: "api_key"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	body, _ := io.ReadAll(req.Body)
	assert.JSONEq(t, `{"authn_descriptors":[{"type":"api_key"}]}`, string(body))
}

// TestUpdateWorkloadRequest_AuthnDescriptorsOptional asserts that a nil
// authn_descriptors array is a no-op on PATCH rather than an error, unlike
// create, which requires at least one descriptor.
func TestUpdateWorkloadRequest_AuthnDescriptorsOptional(t *testing.T) {
	c := newTestClient("http://conjur.test")

	_, err := c.V2().UpdateWorkloadRequest("data/w", WorkloadFields{})
	require.NoError(t, err, "nil authn_descriptors should be a no-op, not an error")
}

// TestUpdateWorkloadRequest_RestrictedTo pins the reason RestrictedTo is a
// pointer: the three states have to be three different request bodies. Unset
// means "leave the server's restrictions alone", an empty slice means "remove
// them all", and the server distinguishes those - it clears on [] and rejects
// null with a 422, so a plain []string with omitempty could only ever express
// one of the two.
func TestUpdateWorkloadRequest_RestrictedTo(t *testing.T) {
	c := newTestClient("http://conjur.test")

	tests := []struct {
		name         string
		restrictedTo *[]string
		expectedBody string
	}{
		{
			name:         "unset omits the attribute",
			restrictedTo: nil,
			expectedBody: `{}`,
		},
		{
			name:         "empty slice sends an empty array, clearing the restrictions",
			restrictedTo: &[]string{},
			expectedBody: `{"restricted_to":[]}`,
		},
		{
			name:         "entries replace the restrictions",
			restrictedTo: &[]string{"1.2.3.4", "10.0.0.0/8"},
			expectedBody: `{"restricted_to":["1.2.3.4","10.0.0.0/8"]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := c.V2().UpdateWorkloadRequest("data/w", WorkloadFields{RestrictedTo: tt.restrictedTo})
			require.NoError(t, err)

			body, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			assert.JSONEq(t, tt.expectedBody, string(body))
		})
	}
}

func TestDeleteWorkloadRequest_Forbidden403(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "protected") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	c := newTestClient(ts.URL)
	req, err := c.V2().DeleteWorkloadRequest("protectedWorkload")
	if err != nil {
		t.Errorf("Error Test failed %s", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("Request error: %s", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", resp.StatusCode)
	}
}

// ---- Tests against a mocked http server ----
//
// Tests above exercise *Request builders directly. Tests below exercise
// wrapper methods (GetWorkload, UpdateWorkload, UpdateAuthnDescriptor) through
// the full SubmitRequest -> authenticate -> parse-response path using
// newWorkloadMockServer's authenticated SaaS client, catching bugs in the
// IsSaaS gate or in response handling.

// TestGetWorkload_IdentifierEncodingEndToEnd asserts that the path the server
// actually receives is correct for both a branch-path identifier - "/"
// separators preserved - and one whose last segment contains a space, which
// must arrive escaped rather than truncating the path.
func TestGetWorkload_IdentifierEncodingEndToEnd(t *testing.T) {
	cases := []struct {
		identifier string
		wantPath   string
	}{
		{"data/test/scratch-workload", "/workloads/data/test/scratch-workload"},
		{"data/test/my workload", "/workloads/data/test/my workload"},
	}

	for _, tc := range cases {
		t.Run(tc.identifier, func(t *testing.T) {
			c := newWorkloadMockServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.wantPath {
					t.Errorf("Unexpected path: %q, want %q", r.URL.Path, tc.wantPath)
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"name":"w","branch":"data/test"}`))
			})

			_, err := c.V2().GetWorkload(tc.identifier)
			require.NoError(t, err)
		})
	}
}

// TestGetWorkload_NotFound404 asserts that a missing workload is surfaced as an
// error rather than as a zero-value Workload.
func TestGetWorkload_NotFound404(t *testing.T) {
	c := newWorkloadMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	workload, err := c.V2().GetWorkload("data/test/no-such-workload")
	require.Error(t, err)
	assert.Nil(t, workload)
}

// TestGetWorkload_InvalidResponseBodyError asserts that a malformed response
// body is surfaced as an error, rather than returning a zero-value Workload
// silently.
func TestGetWorkload_InvalidResponseBodyError(t *testing.T) {
	c := newWorkloadMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`not json`))
	})

	_, err := c.V2().GetWorkload("data/w")
	if err == nil {
		t.Errorf("Expected a JSON unmarshal error, got nil")
	}
}

func TestUpdateWorkload_EndToEnd(t *testing.T) {
	c := newWorkloadMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("Expected PATCH, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"name":"new-client","branch":"data/us-east1/test"}`))
	})

	workload, err := c.V2().UpdateWorkload("data/us-east1/test/new-client", WorkloadFields{Annotations: map[string]string{"team": "devops"}})
	require.NoError(t, err)
	assert.Equal(t, "new-client", workload.Name)
}

func TestCreateWorkload_EndToEnd(t *testing.T) {
	c := newWorkloadMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"name":"testWorkload","branch":"data"}`))
	})

	data, err := c.V2().CreateWorkload(validWorkload())
	require.NoError(t, err)
	assert.JSONEq(t, `{"name":"testWorkload","branch":"data"}`, string(data))
}

// TestCreateWorkload_ErrorResponse asserts that a non-2xx response is
// surfaced as an error through submitAndReadData rather than as a
// successful empty payload.
func TestCreateWorkload_ErrorResponse(t *testing.T) {
	c := newWorkloadMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	})

	_, err := c.V2().CreateWorkload(validWorkload())
	if err == nil {
		t.Errorf("Expected an error for a 409 response, got nil")
	}
}

// TestWorkloadWrappers_PropagateRequestBuildErrors asserts that every wrapper
// surfaces its *Request builder's validation error without ever issuing an
// HTTP request - the mock handler fails the test if it is reached.
func TestWorkloadWrappers_PropagateRequestBuildErrors(t *testing.T) {
	c := newWorkloadMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server should not be called for an invalid request: %s %s", r.Method, r.URL.Path)
	})

	namelessWorkload := validWorkload()
	namelessWorkload.Name = ""

	cases := []struct {
		name        string
		wantMessage string
		call        func() error
	}{
		{"CreateWorkload", "Workload Name", func() error {
			_, err := c.V2().CreateWorkload(namelessWorkload)
			return err
		}},
		{"DeleteWorkload", "Workload ID", func() error {
			_, err := c.V2().DeleteWorkload("")
			return err
		}},
		{"GetWorkload", "Workload ID", func() error {
			_, err := c.V2().GetWorkload("")
			return err
		}},
		{"UpdateWorkload", "Workload ID", func() error {
			_, err := c.V2().UpdateWorkload("", WorkloadFields{})
			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantMessage)
		})
	}
}

func TestDeleteWorkload_EndToEnd(t *testing.T) {
	c := newWorkloadMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("Expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	_, err := c.V2().DeleteWorkload("data/w")
	require.NoError(t, err)
}

// TestUpdateWorkload_InvalidResponseBodyError asserts that a malformed
// response body is surfaced as an error, rather than returning a zero-value
// Workload silently.
func TestUpdateWorkload_InvalidResponseBodyError(t *testing.T) {
	c := newWorkloadMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`not json`))
	})

	_, err := c.V2().UpdateWorkload("data/w", WorkloadFields{Annotations: map[string]string{"a": "b"}})
	if err == nil {
		t.Errorf("Expected a JSON unmarshal error, got nil")
	}
}

// TestWorkloadWrapperMethods_RejectNonSaaS asserts that every new top-level
// wrapper method's IsSaaS guard actually rejects a non-SaaS client.
func TestWorkloadWrapperMethods_RejectNonSaaS(t *testing.T) {
	c := newTestClient("http://conjur.test")

	cases := []struct {
		name string
		call func() error
	}{
		{"CreateWorkload", func() error { _, err := c.V2().CreateWorkload(validWorkload()); return err }},
		{"DeleteWorkload", func() error { _, err := c.V2().DeleteWorkload("data/w"); return err }},
		{"GetWorkload", func() error { _, err := c.V2().GetWorkload("data/w"); return err }},
		{"UpdateWorkload", func() error { _, err := c.V2().UpdateWorkload("data/w", WorkloadFields{}); return err }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil || !strings.Contains(err.Error(), "Workload API") {
				t.Errorf("%s: expected NotSupportedInConjurEnterprise error, got %v", tc.name, err)
			}
		})
	}
}
