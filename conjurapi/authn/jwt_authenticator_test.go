package authn

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJWTAuthenticator_RefreshToken(t *testing.T) {
	// Test that the RefreshToken method calls the Authenticate method
	t.Run("Calls Authenticate with stored JWT", func(t *testing.T) {
		authenticator := JWTAuthenticator{
			Authenticate: func(jwt, hostid string) ([]byte, error) {
				assert.Equal(t, "jwt", jwt)
				assert.Equal(t, "", hostid)
				return []byte("token"), nil
			},
			JWT: "jwt",
		}

		token, err := authenticator.RefreshToken()

		assert.NoError(t, err)
		assert.Equal(t, []byte("token"), token)
	})

	t.Run("Calls Authenticate with JWT from file", func(t *testing.T) {
		tempDir := t.TempDir()
		err := os.WriteFile(filepath.Join(tempDir, "jwt"), []byte("jwt-content"), 0600)
		assert.NoError(t, err)

		authenticator := JWTAuthenticator{
			Authenticate: func(jwt, hostid string) ([]byte, error) {
				assert.Equal(t, "jwt-content", jwt)
				assert.Equal(t, "host-id", hostid)
				return []byte("token"), nil
			},
			JWTFilePath: filepath.Join(tempDir, "jwt"),
			HostID:      "host-id",
		}

		token, err := authenticator.RefreshToken()
		assert.NoError(t, err)
		assert.Equal(t, []byte("token"), token)
	})

	t.Run("Uses K8sTokenPath override when set", func(t *testing.T) {
		// Verifies the K8sTokenPath field takes precedence over the const default.
		// The const default (k8sJWTPath → /var/run/secrets/…) is not covered here
		// because creating that path requires root outside a Kubernetes pod.
		tmpToken := filepath.Join(t.TempDir(), "token")
		err := os.WriteFile(tmpToken, []byte("k8s-jwt-content"), 0600)
		assert.NoError(t, err)

		authenticator := JWTAuthenticator{
			K8sTokenPath: tmpToken,
			Authenticate: func(jwt, hostid string) ([]byte, error) {
				assert.Equal(t, "k8s-jwt-content", jwt)
				assert.Equal(t, "", hostid)
				return []byte("token"), nil
			},
		}

		token, err := authenticator.RefreshToken()
		assert.NoError(t, err)
		assert.Equal(t, []byte("token"), token)
	})

	t.Run("Returns error when Authenticate fails", func(t *testing.T) {
		authenticator := JWTAuthenticator{
			Authenticate: func(jwt, hostid string) ([]byte, error) {
				return nil, assert.AnError
			},
		}

		token, err := authenticator.RefreshToken()
		assert.Error(t, err)
		assert.Nil(t, token)
	})

	t.Run("Returns error when no JWT provided", func(t *testing.T) {
		authenticator := JWTAuthenticator{
			Authenticate: func(jwt, hostid string) ([]byte, error) {
				return nil, nil
			},
		}

		token, err := authenticator.RefreshToken()
		assert.ErrorContains(t, err, "Failed to refresh JWT")
		assert.Nil(t, token)
	})
}

func TestJWTAuthenticator_NeedsTokenRefresh(t *testing.T) {
	t.Run("Returns false", func(t *testing.T) {
		// Test that the NeedsTokenRefresh method always returns false
		authenticator := JWTAuthenticator{}

		assert.False(t, authenticator.NeedsTokenRefresh())
	})
}
