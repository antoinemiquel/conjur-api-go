package conjurapi

import (
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newLdapTestClient creates a minimal Client pointing at the given URL for use by
// *Request() builder methods that don't go through SubmitRequest.
func newLdapTestClient(t *testing.T, applianceURL string) *Client {
	t.Helper()
	tempDir := t.TempDir()
	config := Config{
		Account:           "myaccount",
		ApplianceURL:      applianceURL,
		NetRCPath:         filepath.Join(tempDir, ".netrc"),
		CredentialStorage: "file",
	}
	storage, _ := createStorageProvider(config)
	return &Client{
		config:     config,
		httpClient: &http.Client{},
		storage:    storage,
	}
}

// mockConjurToken is a valid Conjur access token JSON (payload={"sub":"admin","iat":1510753259}).
// The iat is in the past, so ShouldRefresh() returns true — the authenticator will re-fetch it
// each time, which is fine for our mock server that always returns it.
const mockConjurToken = `{"protected":"eyJhbGciOiJjb25qdXIub3JnL3Nsb3NpbG8vdjIiLCJraWQiOiI5M2VjNTEwODRmZTM3Zjc3M2I1ODhlNTYyYWVjZGMxMSJ9","payload":"eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxMDc1MzI1OX0=","signature":"raCufKOf7sKzciZInQTphu1mBbLhAdIJM72ChLB4m5wKWxFnNz_7LawQ9iYEI_we1-tdZtTXoopn_T1qoTplR9_Bo3KkpI5Hj3DB7SmBpR3CSRTnnEwkJ0_aJ8bql5Cbst4i4rSftyEmUqX-FDOqJdAztdi9BUJyLfbeKTW9OGg-QJQzPX1ucB7IpvTFCEjMoO8KUxZpbHj-KpwqAMZRooG4ULBkxp5nSfs-LN27JupU58oRgIfaWASaDmA98O2x6o88MFpxK_M0FeFGuDKewNGrRc8lCOtTQ9cULA080M5CSnruCqu1Qd52r72KIOAfyzNIiBCLTkblz2fZyEkdSKQmZ8J3AakxQE2jyHmMT-eXjfsEIzEt-IRPJIirI3Qm"}`

// newLdapMockServer returns a fully-authenticated Client pointing at a mock
// server that additionally answers /info with a release new enough for the
// LDAP mappings API, which its min-version gate checks.
func newLdapMockServer(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()

	return newAuthenticatedMockServer(t, "", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/info" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"release":"` + LdapMappingsMinVersion + `","services":{"possum":{"desired":"i","status":"i","err":null,"name":"conjur-possum","version":"` + LdapMappingsMinVersion + `","arch":"amd64"}}}`))
			return
		}
		handler(w, r)
	})
}

// ---- Request builder tests ----

func TestLdapGroupMappingRequests(t *testing.T) {
	c := newLdapTestClient(t, "https://conjur.example.com")

	t.Run("CreateGroupMapping request", func(t *testing.T) {
		req, err := c.LdapCreateGroupMappingRequest("ldap1", "dev-team", []string{"group:devs", "group:qa"})
		require.NoError(t, err)
		assert.Equal(t, http.MethodPost, req.Method)
		assert.Contains(t, req.URL.Path, "/authn-ldap/ldap1/myaccount/groups/dev-team")
		assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
		body, _ := io.ReadAll(req.Body)
		assert.JSONEq(t, `{"roles":["group:devs","group:qa"]}`, string(body))
	})

	t.Run("ShowGroupMapping request", func(t *testing.T) {
		req, err := c.LdapShowGroupMappingRequest("ldap1", "dev-team")
		require.NoError(t, err)
		assert.Equal(t, http.MethodGet, req.Method)
		assert.Contains(t, req.URL.Path, "/authn-ldap/ldap1/myaccount/groups/dev-team")
		assert.Empty(t, req.Header.Get("Content-Type"))
	})

	t.Run("ListGroupMappings request", func(t *testing.T) {
		req, err := c.LdapListGroupMappingsRequest("ldap1")
		require.NoError(t, err)
		assert.Equal(t, http.MethodGet, req.Method)
		assert.Contains(t, req.URL.Path, "/authn-ldap/ldap1/myaccount/groups")
		assert.NotContains(t, req.URL.Path, "dev-team")
	})

	t.Run("DeleteGroupMapping request", func(t *testing.T) {
		req, err := c.LdapDeleteGroupMappingRequest("ldap1", "dev-team")
		require.NoError(t, err)
		assert.Equal(t, http.MethodDelete, req.Method)
		assert.Contains(t, req.URL.Path, "/authn-ldap/ldap1/myaccount/groups/dev-team")
	})

	t.Run("URL-encodes group name with spaces", func(t *testing.T) {
		req, err := c.LdapShowGroupMappingRequest("ldap1", "my group name")
		require.NoError(t, err)
		// url.PathEscape encodes spaces as %20; use EscapedPath() since RawPath may be empty
		assert.Contains(t, req.URL.EscapedPath(), "my%20group%20name")
	})

	t.Run("URL-encodes service ID with spaces", func(t *testing.T) {
		req, err := c.LdapShowGroupMappingRequest("my service", "group1")
		require.NoError(t, err)
		assert.Contains(t, req.URL.EscapedPath(), "my%20service")
	})
}

func TestLdapUserMappingRequests(t *testing.T) {
	c := newLdapTestClient(t, "https://conjur.example.com")

	t.Run("CreateUserMapping request", func(t *testing.T) {
		req, err := c.LdapCreateUserMappingRequest("ldap1", "jan.k", []string{"group:devs"})
		require.NoError(t, err)
		assert.Equal(t, http.MethodPost, req.Method)
		assert.Contains(t, req.URL.Path, "/authn-ldap/ldap1/myaccount/users/jan.k")
		assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
		body, _ := io.ReadAll(req.Body)
		assert.JSONEq(t, `{"roles":["group:devs"]}`, string(body))
	})

	t.Run("ShowUserMapping request", func(t *testing.T) {
		req, err := c.LdapShowUserMappingRequest("ldap1", "jan.k")
		require.NoError(t, err)
		assert.Equal(t, http.MethodGet, req.Method)
		assert.Contains(t, req.URL.Path, "/authn-ldap/ldap1/myaccount/users/jan.k")
	})

	t.Run("ListUserMappings request", func(t *testing.T) {
		req, err := c.LdapListUserMappingsRequest("ldap1")
		require.NoError(t, err)
		assert.Equal(t, http.MethodGet, req.Method)
		assert.Contains(t, req.URL.Path, "/authn-ldap/ldap1/myaccount/users")
		assert.NotContains(t, req.URL.Path, "jan.k")
	})

	t.Run("DeleteUserMapping request", func(t *testing.T) {
		req, err := c.LdapDeleteUserMappingRequest("ldap1", "jan.k")
		require.NoError(t, err)
		assert.Equal(t, http.MethodDelete, req.Method)
		assert.Contains(t, req.URL.Path, "/authn-ldap/ldap1/myaccount/users/jan.k")
	})
}

// ---- Full-flow tests with mock HTTP server ----

func TestLdapCreateGroupMapping(t *testing.T) {
	testCases := []struct {
		name          string
		statusCode    int
		responseBody  string
		expectError   bool
		expectedCode  int
		expectedGroup string
		expectedRoles []string
	}{
		{
			name:          "success 201",
			statusCode:    http.StatusCreated,
			responseBody:  `{"ldap_group":"dev-team","roles":["conjur:group:devs"]}`,
			expectedGroup: "dev-team",
			expectedRoles: []string{"conjur:group:devs"},
		},
		{
			name:         "403 forbidden",
			statusCode:   http.StatusForbidden,
			responseBody: "",
			expectError:  true,
			expectedCode: 403,
		},
		{
			name:         "404 role not found",
			statusCode:   http.StatusNotFound,
			responseBody: `{"error":{"code":"not_found","message":"Role 'conjur:group:nonexistent' does not exist"}}`,
			expectError:  true,
			expectedCode: 404,
		},
		{
			name:         "422 missing roles",
			statusCode:   http.StatusUnprocessableEntity,
			responseBody: `{"error":{"code":"unprocessable_entity","message":"roles parameter is required"}}`,
			expectError:  true,
			expectedCode: 422,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := newLdapMockServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				w.Write([]byte(tc.responseBody))
			})

			result, err := client.LdapCreateGroupMapping("ldap1", "dev-team", []string{"group:devs"})

			if tc.expectError {
				require.Error(t, err)
				var cerr *response.ConjurError
				require.True(t, errors.As(err, &cerr))
				assert.Equal(t, tc.expectedCode, cerr.Code)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedGroup, result.LdapGroup)
				assert.Equal(t, tc.expectedRoles, result.Roles)
			}
		})
	}
}

func TestLdapShowGroupMapping(t *testing.T) {
	testCases := []struct {
		name          string
		statusCode    int
		responseBody  string
		expectError   bool
		expectedCode  int
		expectedGroup string
	}{
		{
			name:          "success 200",
			statusCode:    http.StatusOK,
			responseBody:  `{"ldap_group":"dev-team","roles":["conjur:group:devs"]}`,
			expectedGroup: "dev-team",
		},
		{
			name:         "404 not found",
			statusCode:   http.StatusNotFound,
			responseBody: `{"error":{"code":"not_found","message":"Group mapping 'dev-team' not found"}}`,
			expectError:  true,
			expectedCode: 404,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := newLdapMockServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				w.Write([]byte(tc.responseBody))
			})

			result, err := client.LdapShowGroupMapping("ldap1", "dev-team")

			if tc.expectError {
				require.Error(t, err)
				var cerr *response.ConjurError
				require.True(t, errors.As(err, &cerr))
				assert.Equal(t, tc.expectedCode, cerr.Code)
				assert.Contains(t, cerr.Details.Message, "dev-team")
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedGroup, result.LdapGroup)
			}
		})
	}
}

func TestLdapListGroupMappings(t *testing.T) {
	testCases := []struct {
		name         string
		statusCode   int
		responseBody string
		expectError  bool
		expectedKeys []string
	}{
		{
			name:         "success with entries",
			statusCode:   http.StatusOK,
			responseBody: `{"keys":["dev-team","qa-team"]}`,
			expectedKeys: []string{"dev-team", "qa-team"},
		},
		{
			name:         "success empty list",
			statusCode:   http.StatusOK,
			responseBody: `{"keys":[]}`,
			expectedKeys: []string{},
		},
		{
			name:         "403 forbidden",
			statusCode:   http.StatusForbidden,
			responseBody: "",
			expectError:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := newLdapMockServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				w.Write([]byte(tc.responseBody))
			})

			result, err := client.LdapListGroupMappings("ldap1")

			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedKeys, result.Keys)
			}
		})
	}
}

func TestLdapDeleteGroupMapping(t *testing.T) {
	testCases := []struct {
		name         string
		statusCode   int
		responseBody string
		expectError  bool
		expectedCode int
	}{
		{
			name:       "success 204",
			statusCode: http.StatusNoContent,
		},
		{
			name:         "404 not found",
			statusCode:   http.StatusNotFound,
			responseBody: `{"error":{"code":"not_found","message":"Group mapping 'dev-team' not found"}}`,
			expectError:  true,
			expectedCode: 404,
		},
		{
			name:         "403 forbidden",
			statusCode:   http.StatusForbidden,
			expectError:  true,
			expectedCode: 403,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := newLdapMockServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				if tc.responseBody != "" {
					w.Write([]byte(tc.responseBody))
				}
			})

			err := client.LdapDeleteGroupMapping("ldap1", "dev-team")

			if tc.expectError {
				require.Error(t, err)
				var cerr *response.ConjurError
				require.True(t, errors.As(err, &cerr))
				assert.Equal(t, tc.expectedCode, cerr.Code)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestLdapCreateUserMapping(t *testing.T) {
	testCases := []struct {
		name             string
		statusCode       int
		responseBody     string
		expectError      bool
		expectedCode     int
		expectedUsername string
	}{
		{
			name:             "success 201",
			statusCode:       http.StatusCreated,
			responseBody:     `{"ldap_username":"jan.k","roles":["conjur:group:devs"]}`,
			expectedUsername: "jan.k",
		},
		{
			name:         "403 forbidden",
			statusCode:   http.StatusForbidden,
			expectError:  true,
			expectedCode: 403,
		},
		{
			name:         "422 missing roles",
			statusCode:   http.StatusUnprocessableEntity,
			responseBody: `{"error":{"code":"unprocessable_entity","message":"roles parameter is required"}}`,
			expectError:  true,
			expectedCode: 422,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := newLdapMockServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				w.Write([]byte(tc.responseBody))
			})

			result, err := client.LdapCreateUserMapping("ldap1", "jan.k", []string{"group:devs"})

			if tc.expectError {
				require.Error(t, err)
				var cerr *response.ConjurError
				require.True(t, errors.As(err, &cerr))
				assert.Equal(t, tc.expectedCode, cerr.Code)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedUsername, result.LdapUsername)
			}
		})
	}
}

func TestLdapShowUserMapping(t *testing.T) {
	testCases := []struct {
		name             string
		statusCode       int
		responseBody     string
		expectError      bool
		expectedCode     int
		expectedUsername string
	}{
		{
			name:             "success 200",
			statusCode:       http.StatusOK,
			responseBody:     `{"ldap_username":"jan.k","roles":["conjur:group:devs"]}`,
			expectedUsername: "jan.k",
		},
		{
			name:         "404 not found",
			statusCode:   http.StatusNotFound,
			responseBody: `{"error":{"code":"not_found","message":"User mapping 'jan.k' not found"}}`,
			expectError:  true,
			expectedCode: 404,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := newLdapMockServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				w.Write([]byte(tc.responseBody))
			})

			result, err := client.LdapShowUserMapping("ldap1", "jan.k")

			if tc.expectError {
				require.Error(t, err)
				var cerr *response.ConjurError
				require.True(t, errors.As(err, &cerr))
				assert.Equal(t, tc.expectedCode, cerr.Code)
				assert.Contains(t, cerr.Details.Message, "jan.k")
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedUsername, result.LdapUsername)
			}
		})
	}
}

func TestLdapListUserMappings(t *testing.T) {
	testCases := []struct {
		name         string
		statusCode   int
		responseBody string
		expectError  bool
		expectedKeys []string
	}{
		{
			name:         "success with entries",
			statusCode:   http.StatusOK,
			responseBody: `{"keys":["jan.k","anna.n"]}`,
			expectedKeys: []string{"jan.k", "anna.n"},
		},
		{
			name:         "success empty list",
			statusCode:   http.StatusOK,
			responseBody: `{"keys":[]}`,
			expectedKeys: []string{},
		},
		{
			name:         "403 forbidden",
			statusCode:   http.StatusForbidden,
			responseBody: "",
			expectError:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := newLdapMockServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				w.Write([]byte(tc.responseBody))
			})

			result, err := client.LdapListUserMappings("ldap1")

			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedKeys, result.Keys)
			}
		})
	}
}

func TestLdapDeleteUserMapping(t *testing.T) {
	testCases := []struct {
		name         string
		statusCode   int
		responseBody string
		expectError  bool
		expectedCode int
	}{
		{
			name:       "success 204",
			statusCode: http.StatusNoContent,
		},
		{
			name:         "404 not found",
			statusCode:   http.StatusNotFound,
			responseBody: `{"error":{"code":"not_found","message":"User mapping 'jan.k' not found"}}`,
			expectError:  true,
			expectedCode: 404,
		},
		{
			name:         "403 forbidden",
			statusCode:   http.StatusForbidden,
			expectError:  true,
			expectedCode: 403,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := newLdapMockServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				if tc.responseBody != "" {
					w.Write([]byte(tc.responseBody))
				}
			})

			err := client.LdapDeleteUserMapping("ldap1", "jan.k")

			if tc.expectError {
				require.Error(t, err)
				var cerr *response.ConjurError
				require.True(t, errors.As(err, &cerr))
				assert.Equal(t, tc.expectedCode, cerr.Code)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// Verifies that path segments are correctly separated (groups vs users).
func TestLdapMappingPathSegments(t *testing.T) {
	c := newLdapTestClient(t, "https://conjur.example.com")

	groupReq, err := c.LdapCreateGroupMappingRequest("svc", "mygroup", []string{"group:a"})
	require.NoError(t, err)
	assert.True(t, strings.Contains(groupReq.URL.Path, "/groups/"), "group path must contain /groups/")
	assert.False(t, strings.Contains(groupReq.URL.Path, "/users/"), "group path must not contain /users/")

	userReq, err := c.LdapCreateUserMappingRequest("svc", "myuser", []string{"group:a"})
	require.NoError(t, err)
	assert.True(t, strings.Contains(userReq.URL.Path, "/users/"), "user path must contain /users/")
	assert.False(t, strings.Contains(userReq.URL.Path, "/groups/"), "user path must not contain /groups/")
}
