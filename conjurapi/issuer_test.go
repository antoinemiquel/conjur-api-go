package conjurapi

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const TestAccessKeyID = "AKIAIOSFODNN7EXAMPLE"
const TestSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

const (
	issuerAWSAccessKeyVariable       = "aws-access-key-id"
	issuerAWSSecretKeyVariable       = "aws-secret-access-key"
	issuerAWSAccessKeyAltVariable    = "aws-access-key-id-2"
	issuerAWSSecretKeyAltVariable    = "aws-secret-access-key-2"
	issuerAWSAccessKeyRefPath        = "data/test/aws-access-key-id"
	issuerAWSSecretKeyRefPath        = "data/test/aws-secret-access-key"
	issuerAWSAccessKeyAltRefPath     = "data/test/aws-access-key-id-2"
	issuerAWSSecretKeyAltRefPath     = "data/test/aws-secret-access-key-2"
	issuerAWSInvalidAccessKeyRefPath = "data/test/aws-invalid-access-key-id"
	issuerAWSInvalidSecretKeyRefPath = "data/test/aws-invalid-secret-access-key"
)

const issuerAWSCredentialPolicy = `
- !variable aws-access-key-id
- !variable aws-secret-access-key
`

const issuerAWSCredentialAltPolicy = `
- !variable aws-access-key-id-2
- !variable aws-secret-access-key-2
`

const issuerAWSInvalidCredentialPolicy = `
- !variable aws-invalid-access-key-id
- !variable aws-invalid-secret-access-key
`

func issuerAWSData() map[string]interface{} {
	return map[string]interface{}{
		"access_key_id_secret_ref": map[string]interface{}{
			"id": issuerAWSAccessKeyRefPath,
		},
		"secret_access_key_secret_ref": map[string]interface{}{
			"id": issuerAWSSecretKeyRefPath,
		},
	}
}

func issuerAWSUpdateData() map[string]interface{} {
	return map[string]interface{}{
		"access_key_id_secret_ref": map[string]interface{}{
			"id": issuerAWSAccessKeyAltRefPath,
		},
		"secret_access_key_secret_ref": map[string]interface{}{
			"id": issuerAWSSecretKeyAltRefPath,
		},
	}
}

func issuerAWSInvalidData() map[string]interface{} {
	return map[string]interface{}{
		"access_key_id_secret_ref": map[string]interface{}{
			"id": issuerAWSInvalidAccessKeyRefPath,
		},
		"secret_access_key_secret_ref": map[string]interface{}{
			"id": issuerAWSInvalidSecretKeyRefPath,
		},
	}
}

func newTestAWSIssuer(id string, maxTTL int) Issuer {
	return Issuer{
		ID:     id,
		Type:   "aws",
		MaxTTL: maxTTL,
		Data:   issuerAWSData(),
	}
}

func setupIssuerAWSCredentials(t *testing.T, utils TestUtils, conjur *Client) {
	t.Helper()

	_, err := conjur.LoadPolicy(
		PolicyModePost,
		utils.PolicyBranch(),
		strings.NewReader(issuerAWSCredentialPolicy),
	)
	assert.NoError(t, err)
	assert.NoError(t, conjur.AddSecret(utils.IDWithPath(issuerAWSAccessKeyVariable), TestAccessKeyID))
	assert.NoError(t, conjur.AddSecret(utils.IDWithPath(issuerAWSSecretKeyVariable), TestSecretAccessKey))
}

func setupIssuerAWSAltCredentials(t *testing.T, utils TestUtils, conjur *Client) {
	t.Helper()

	_, err := conjur.LoadPolicy(
		PolicyModePost,
		utils.PolicyBranch(),
		strings.NewReader(issuerAWSCredentialAltPolicy),
	)
	assert.NoError(t, err)
	assert.NoError(t, conjur.AddSecret(utils.IDWithPath(issuerAWSAccessKeyAltVariable), "AKIAIOSFODNN7EXAMPLE2"))
	assert.NoError(t, conjur.AddSecret(utils.IDWithPath(issuerAWSSecretKeyAltVariable), "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY2"))
}

func setupIssuerAWSInvalidCredentials(t *testing.T, utils TestUtils, conjur *Client) {
	t.Helper()

	_, err := conjur.LoadPolicy(
		PolicyModePost,
		utils.PolicyBranch(),
		strings.NewReader(issuerAWSInvalidCredentialPolicy),
	)
	assert.NoError(t, err)
	assert.NoError(t, conjur.AddSecret(utils.IDWithPath("aws-invalid-access-key-id"), "invalid"))
	assert.NoError(t, conjur.AddSecret(utils.IDWithPath("aws-invalid-secret-access-key"), "invalid"))
}

func prepareIssuerIntegrationTest(t *testing.T, utils TestUtils, conjur *Client) {
	t.Helper()
	setupIssuerAWSCredentials(t, utils, conjur)
	setupIssuerAWSAltCredentials(t, utils, conjur)
	setupIssuerAWSInvalidCredentials(t, utils, conjur)
}

func assertIssuerAWSCredentialsMasked(t *testing.T, issuer Issuer) {
	t.Helper()

	accessRef, hasAccessRef := issuer.Data["access_key_id_secret_ref"].(map[string]interface{})
	secretRef, hasSecretRef := issuer.Data["secret_access_key_secret_ref"].(map[string]interface{})
	assert.True(t, hasAccessRef)
	assert.True(t, hasSecretRef)
	assert.Equal(t, issuerAWSAccessKeyRefPath, accessRef["id"])
	assert.Equal(t, issuerAWSSecretKeyRefPath, secretRef["id"])
	if secretKey, ok := issuer.Data["secret_access_key"].(string); ok {
		assert.Equal(t, "*****", secretKey)
	}
}

func assertIssuerAWSPrimaryCredentials(t *testing.T, issuer Issuer) {
	t.Helper()

	accessRef, ok := issuer.Data["access_key_id_secret_ref"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, issuerAWSAccessKeyRefPath, accessRef["id"])
}

func assertIssuerAWSAltCredentials(t *testing.T, issuer Issuer) {
	t.Helper()

	accessRef, ok := issuer.Data["access_key_id_secret_ref"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, issuerAWSAccessKeyAltRefPath, accessRef["id"])
}

func TestClient_CreateIssuer(t *testing.T) {
	config := &Config{}
	config.mergeEnv()

	utils, err := NewTestUtils(config)
	assert.NoError(t, err)

	_, err = utils.Setup("#")
	assert.NoError(t, err)

	conjur := utils.Client()
	prepareIssuerIntegrationTest(t, utils, conjur)

	testCases := []struct {
		name         string
		id           string
		issuerType   string
		maxTTL       int
		data         map[string]interface{}
		assertError  func(*testing.T, error)
		assertIssuer func(*testing.T, Issuer)
	}{
		{
			name:       "Create an Issuer",
			id:         "test-issuer",
			issuerType: "aws",
			maxTTL:     900,
			assertError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			assertIssuer: func(t *testing.T, issuer Issuer) {
				assert.Equal(t, "test-issuer", issuer.ID)
				assert.Equal(t, "aws", issuer.Type)
				assert.Equal(t, 900, issuer.MaxTTL)
				assertIssuerAWSCredentialsMasked(t, issuer)
				assert.NotEmpty(t, issuer.CreatedAt)
				assert.NotEmpty(t, issuer.ModifiedAt)
			},
		},
		{
			name:       "Invalid issuer",
			id:         "test-issuer",
			issuerType: "aws",
			maxTTL:     900,
			data:       issuerAWSInvalidData(),
			assertError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Regexp(
					t,
					// Secrets Manager SaaS returns "Entity", Enterprise returns "Content"
					"422 Unprocessable (Content|Entity)",
					err.Error(),
				)
			},
			assertIssuer: func(t *testing.T, issuer Issuer) {
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.data
			if data == nil {
				data = issuerAWSData()
			}

			issuer := Issuer{
				ID:     tc.id,
				Type:   tc.issuerType,
				MaxTTL: tc.maxTTL,
				Data:   data,
			}

			createdIssuer, err := conjur.CreateIssuer(issuer)
			tc.assertError(t, err)

			if err != nil {
				return
			}

			tc.assertIssuer(t, createdIssuer)

			// Clean up the Issuer, if it was created
			err = conjur.DeleteIssuer(tc.id, false)
			assert.NoError(t, err)
		})
	}
}

func TestClient_DeleteIssuer(t *testing.T) {
	config := &Config{}
	config.mergeEnv()

	utils, err := NewTestUtils(config)
	assert.NoError(t, err)

	_, err = utils.Setup("#")
	assert.NoError(t, err)

	conjur := utils.Client()
	prepareIssuerIntegrationTest(t, utils, conjur)

	testCases := []struct {
		name        string
		id          string
		keepSecrets bool
		setup       func(*testing.T)
		assert      func(*testing.T, error)
	}{
		{
			name:        "Delete an Issuer (Don't keep secrets)",
			id:          "test-issuer",
			keepSecrets: false,
			setup: func(t *testing.T) {
				_, err := conjur.CreateIssuer(newTestAWSIssuer("test-issuer", 900))
				assert.NoError(t, err)

				secretPolicy := `
- !variable
  id: dynamic/test-issuer-secret
  annotations:
    dynamic/issuer: test-issuer
    dynamic/method: federation-token
`

				_, err = conjur.LoadPolicy(
					PolicyModePost,
					"data",
					strings.NewReader(secretPolicy),
				)
				assert.NoError(t, err)
			},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)

				exists, err := conjur.ResourceExists(
					"variable:data/dynamic/test-issuer-secret",
				)
				assert.NoError(t, err)
				assert.False(t, exists)
			},
		},
		{
			name:        "Delete an Issuer (Keep secrets)",
			id:          "test-issuer",
			keepSecrets: true,
			setup: func(t *testing.T) {
				_, err := conjur.CreateIssuer(newTestAWSIssuer("test-issuer", 900))
				assert.NoError(t, err)

				secretPolicy := `
- !variable
  id: dynamic/test-issuer-secret
  annotations:
    dynamic/issuer: test-issuer
    dynamic/method: federation-token
`

				_, err = conjur.LoadPolicy(
					PolicyModePost,
					"data",
					strings.NewReader(secretPolicy),
				)
				assert.NoError(t, err)
			},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)

				exists, err := conjur.ResourceExists(
					"variable:data/dynamic/test-issuer-secret",
				)
				assert.NoError(t, err)
				assert.True(t, exists)
			},
		},
		{
			name:        "Delete non-existent issuer",
			id:          "test-issuer",
			keepSecrets: true,
			setup:       func(t *testing.T) {},
			assert: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Regexp(
					t,
					"404 Not Found. Issuer not found.",
					err.Error(),
				)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup(t)

			err := conjur.DeleteIssuer(tc.id, tc.keepSecrets)

			tc.assert(t, err)
		})
	}
}

func TestClient_Issuer(t *testing.T) {
	config := &Config{}
	config.mergeEnv()

	utils, err := NewTestUtils(config)
	assert.NoError(t, err)

	_, err = utils.Setup("#")
	assert.NoError(t, err)

	conjur := utils.Client()
	prepareIssuerIntegrationTest(t, utils, conjur)

	testCases := []struct {
		name         string
		id           string
		setup        func(*testing.T)
		cleanup      func(*testing.T)
		assertError  func(*testing.T, error)
		assertIssuer func(*testing.T, Issuer)
	}{
		{
			name: "Get an Issuer",
			id:   "test-issuer-2",
			setup: func(t *testing.T) {
				_, err := conjur.CreateIssuer(newTestAWSIssuer("test-issuer-2", 900))
				assert.NoError(t, err)
			},
			assertError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			assertIssuer: func(t *testing.T, issuer Issuer) {
				assert.Equal(t, "test-issuer-2", issuer.ID)
				assert.Equal(t, "aws", issuer.Type)
				assert.Equal(t, 900, issuer.MaxTTL)
				assertIssuerAWSCredentialsMasked(t, issuer)
				assert.NotEmpty(t, issuer.CreatedAt)
				assert.NotEmpty(t, issuer.ModifiedAt)
			},
			cleanup: func(t *testing.T) {
				err := conjur.DeleteIssuer("test-issuer-2", false)
				assert.NoError(t, err)
			},
		},
		{
			name:    "Get non-existing Issuer",
			id:      "test-issuer",
			setup:   func(t *testing.T) {},
			cleanup: func(t *testing.T) {},
			assertError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Equal(
					t,
					"404 Not Found. Issuer not found.",
					err.Error(),
				)
			},
			assertIssuer: func(t *testing.T, issuer Issuer) {},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			tc.setup(t)
			defer tc.cleanup(t)

			issuer, err := conjur.Issuer(tc.id)
			tc.assertError(t, err)

			if err != nil {
				return
			}

			tc.assertIssuer(t, issuer)
		})
	}
}

func TestClient_Issuers(t *testing.T) {
	config := &Config{}
	config.mergeEnv()

	utils, err := NewTestUtils(config)
	assert.NoError(t, err)

	_, err = utils.Setup("#")
	assert.NoError(t, err)

	conjur := utils.Client()
	prepareIssuerIntegrationTest(t, utils, conjur)

	testCases := []struct {
		name          string
		id            string
		setup         func(*testing.T)
		cleanup       func(*testing.T)
		assertError   func(*testing.T, error)
		assertIssuers func(*testing.T, []Issuer)
	}{
		{
			name: "No issuers ever created",
			setup: func(t *testing.T) {
			},
			assertError: func(t *testing.T, err error) {
				if isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {
					// In Secrets Manager SaaS, the issuer branch is pre-created
					assert.NoError(t, err)
				} else {
					// In this case, the Issuer policy doesn't yet exist
					// so we expect a 403 Forbidden error
					assert.Error(t, err, "403 Forbidden")
				}
			},
			assertIssuers: func(t *testing.T, issuers []Issuer) {
				if isConjurCloudURL(os.Getenv("CONJUR_APPLIANCE_URL")) {
					assert.Empty(t, issuers)
				}
			},
			cleanup: func(t *testing.T) {
			},
		},
		{
			name: "No current issuers",
			setup: func(t *testing.T) {
				// Create and delete an issuer to ensure that the
				// issuer policy exists, but there are no current issuers
				// in the system.
				issuer := newTestAWSIssuer("no-current-issuer", 900)

				issuer, err := conjur.CreateIssuer(issuer)
				assert.NoError(t, err)

				err = conjur.DeleteIssuer(issuer.ID, false)
				assert.NoError(t, err)
			},
			assertError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			assertIssuers: func(t *testing.T, issuers []Issuer) {
				assert.Empty(t, issuers)
			},
			cleanup: func(t *testing.T) {
			},
		},
		{
			name: "Single issuer",
			setup: func(t *testing.T) {
				// Create and delete an issuer to ensure that the
				// issuer policy exists, but there are no current issuers
				// in the system.
				_, err := conjur.CreateIssuer(newTestAWSIssuer("single-issuer", 900))
				assert.NoError(t, err)
			},
			assertError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			assertIssuers: func(t *testing.T, issuers []Issuer) {
				assert.Len(t, issuers, 1)
			},
			cleanup: func(t *testing.T) {
				err = conjur.DeleteIssuer("single-issuer", false)
				assert.NoError(t, err)
			},
		},
		{
			name: "100 issuers",
			setup: func(t *testing.T) {
				for i := 0; i < 100; i++ {
					_, err := conjur.CreateIssuer(newTestAWSIssuer(fmt.Sprintf("issuer-%d", i), 900))
					assert.NoError(t, err)
				}
			},
			assertError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			assertIssuers: func(t *testing.T, issuers []Issuer) {
				assert.Len(t, issuers, 100)
			},
			cleanup: func(t *testing.T) {
				for i := 0; i < 100; i++ {
					err = conjur.DeleteIssuer(fmt.Sprintf("issuer-%d", i), false)
					assert.NoError(t, err)
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			tc.setup(t)
			defer tc.cleanup(t)

			issuers, err := conjur.Issuers()
			tc.assertError(t, err)

			if err != nil {
				return
			}

			tc.assertIssuers(t, issuers)
		})
	}
}

func TestClient_UpdateIssuer(t *testing.T) {
	config := &Config{}
	config.mergeEnv()

	utils, err := NewTestUtils(config)
	assert.NoError(t, err)

	_, err = utils.Setup("#")
	assert.NoError(t, err)

	conjur := utils.Client()
	prepareIssuerIntegrationTest(t, utils, conjur)

	testCases := []struct {
		name         string
		id           string
		update       func() IssuerUpdate
		setup        func(*testing.T)
		cleanup      func(*testing.T)
		assertError  func(*testing.T, error)
		assertIssuer func(*testing.T, Issuer)
	}{
		{
			name: "Update issuer",
			id:   "update-issuer",
			setup: func(t *testing.T) {
				_, err := conjur.CreateIssuer(newTestAWSIssuer("update-issuer", 900))
				assert.NoError(t, err)
			},
			update: func() IssuerUpdate {
				ttl := 1000
				return IssuerUpdate{
					MaxTTL: &ttl,
					Data:   issuerAWSUpdateData(),
				}
			},
			assertError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			assertIssuer: func(t *testing.T, issuer Issuer) {
				assert.Equal(t, issuer.MaxTTL, 1000)
				assertIssuerAWSAltCredentials(t, issuer)
			},
			cleanup: func(t *testing.T) {
				err := conjur.DeleteIssuer("update-issuer", false)
				assert.NoError(t, err)
			},
		},
		{
			name:  "Update non-existent issuer",
			id:    "non-existent-issuer",
			setup: func(t *testing.T) {},
			update: func() IssuerUpdate {
				ttl := 1000
				return IssuerUpdate{
					MaxTTL: &ttl,
					Data:   issuerAWSUpdateData(),
				}
			},
			assertError: func(t *testing.T, err error) {
				assert.Error(t, err, "404 Not Found. Issuer not found.")
			},
			assertIssuer: func(t *testing.T, issuer Issuer) {},
			cleanup:      func(t *testing.T) {},
		},
		{
			name: "Empty issuer update",
			id:   "empty-update-issuer",
			setup: func(t *testing.T) {
				_, err := conjur.CreateIssuer(newTestAWSIssuer("empty-update-issuer", 900))
				assert.NoError(t, err)
			},
			update: func() IssuerUpdate {
				return IssuerUpdate{}
			},
			assertError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			assertIssuer: func(t *testing.T, issuer Issuer) {
				assert.Equal(t, issuer.MaxTTL, 900)
				assertIssuerAWSPrimaryCredentials(t, issuer)
			},
			cleanup: func(t *testing.T) {
				err := conjur.DeleteIssuer("empty-update-issuer", false)
				assert.NoError(t, err)
			},
		},
		{
			name: "Invalid max TTL",
			id:   "invalid-ttl-update",
			setup: func(t *testing.T) {
				_, err := conjur.CreateIssuer(newTestAWSIssuer("invalid-ttl-update", 900))
				assert.NoError(t, err)
			},
			update: func() IssuerUpdate {
				ttl := 800
				return IssuerUpdate{
					MaxTTL: &ttl,
				}
			},
			assertError: func(t *testing.T, err error) {
				assert.ErrorContains(
					t,
					err,
					"400 Bad Request. the 'max_ttl' parameter must be",
				)
			},
			assertIssuer: func(t *testing.T, issuer Issuer) {
			},
			cleanup: func(t *testing.T) {
				err := conjur.DeleteIssuer("invalid-ttl-update", false)
				assert.NoError(t, err)
			},
		},
		{
			name: "Empty data",
			id:   "empty-data-update",
			setup: func(t *testing.T) {
				_, err := conjur.CreateIssuer(newTestAWSIssuer("empty-data-update", 900))
				assert.NoError(t, err)
			},
			update: func() IssuerUpdate {
				return IssuerUpdate{
					Data: map[string]interface{}{},
				}
			},
			assertError: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
			assertIssuer: func(t *testing.T, issuer Issuer) {
				assertIssuerAWSPrimaryCredentials(t, issuer)
			},
			cleanup: func(t *testing.T) {
				err := conjur.DeleteIssuer("empty-data-update", false)
				assert.NoError(t, err)
			},
		},
		{
			name: "Invalid data",
			id:   "invalid-data-update",
			setup: func(t *testing.T) {
				_, err := conjur.CreateIssuer(newTestAWSIssuer("invalid-data-update", 900))
				assert.NoError(t, err)
			},
			update: func() IssuerUpdate {
				return IssuerUpdate{
					Data: map[string]interface{}{
						"access_key_id_secret_ref": map[string]interface{}{
							"id": issuerAWSAccessKeyRefPath,
						},
					},
				}
			},
			assertError: func(t *testing.T, err error) {
				assert.Error(t, err)
				assert.Regexp(t, "422 Unprocessable (Content|Entity)", err.Error())
			},
			assertIssuer: func(t *testing.T, issuer Issuer) {
			},
			cleanup: func(t *testing.T) {
				err := conjur.DeleteIssuer("invalid-data-update", false)
				assert.NoError(t, err)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup(t)
			defer tc.cleanup(t)

			issuer, err := conjur.UpdateIssuer(tc.id, tc.update())
			tc.assertError(t, err)

			if err != nil {
				return
			}

			tc.assertIssuer(t, issuer)
		})
	}
}
