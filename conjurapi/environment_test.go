package conjurapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvironmentType_Set(t *testing.T) {
	tests := []struct {
		name    string
		e       EnvironmentType
		value   string
		wantErr assert.ErrorAssertionFunc
	}{{
		name:    "Empty",
		e:       EnvironmentType(""),
		value:   "",
		wantErr: assert.Error,
	}, {
		name:    "Invalid",
		e:       EnvironmentType(""),
		value:   "invalid",
		wantErr: assert.Error,
	}, {
		name:    "Set to cloud",
		e:       EnvironmentSaaS,
		value:   "cloud",
		wantErr: assert.NoError,
	}, {
		name:    "Set to cloud short",
		e:       EnvironmentSaaS,
		value:   "CC",
		wantErr: assert.NoError,
	}, {
		name:    "Set to enterprise",
		e:       EnvironmentSH,
		value:   "enterprise",
		wantErr: assert.NoError,
	}, {
		name:    "Set to enterprise short",
		e:       EnvironmentSH,
		value:   "CE",
		wantErr: assert.NoError,
	}, {
		name:    "Set to oss",
		e:       EnvironmentOSS,
		value:   "oss",
		wantErr: assert.NoError,
	}, {
		name:    "Set to oss short",
		e:       EnvironmentOSS,
		value:   "OSS",
		wantErr: assert.NoError,
	}, {
		name:    "Set to open-source",
		e:       EnvironmentOSS,
		value:   "open-source",
		wantErr: assert.NoError,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.wantErr(t, tt.e.Set(tt.value), fmt.Sprintf("Set(%v)", tt.value))
		})
	}
}

func TestEnvironmentType_String(t *testing.T) {
	tests := []struct {
		name string
		e    EnvironmentType
		want string
	}{{
		name: "Empty",
		e:    EnvironmentType(""),
		want: "",
	}, {
		name: "SaaS",
		e:    EnvironmentSaaS,
		want: "saas",
	}, {
		name: "Self-Hosted",
		e:    EnvironmentSH,
		want: "self-hosted",
	}, {
		name: "OSS",
		e:    EnvironmentOSS,
		want: "oss",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, tt.e.String(), "String()")
		})
	}
}

func Test_defaultEnvironment(t *testing.T) {
	t.Run("static detection", func(t *testing.T) {
		tests := []struct {
			name string
			url  string
			want EnvironmentType
		}{{
			name: "Empty",
			url:  "",
			want: EnvironmentSH,
		}, {
			name: "Secrets Manager SaaS",
			url:  "https://tenant.secretsmgr.cyberark.cloud",
			want: EnvironmentSaaS,
		}, {
			name: "Self-hosted without /api base path",
			url:  "https://conjur.example.com",
			want: EnvironmentSH,
		}}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				config := Config{ApplianceURL: tt.url}
				assert.Equalf(t, tt.want, defaultEnvironment(config, false), "defaultEnvironment(%v)", tt.url)
			})
		}
	})

	t.Run("ambiguous /api base path", func(t *testing.T) {
		tests := []struct {
			name         string
			infoResponse string
			rootResponse string
			want         EnvironmentType
		}{{
			name:         "Edge with /api base path",
			infoResponse: "",
			rootResponse: "",
			want:         EnvironmentSaaS,
		}, {
			name:         "Self-hosted enterprise with /api base path",
			infoResponse: mockEnterpriseInfo,
			rootResponse: "",
			want:         EnvironmentSH,
		}, {
			name:         "Self-hosted OSS with /api base path",
			infoResponse: "",
			rootResponse: `{"version":"1.21.0"}`,
			want:         EnvironmentSH,
		}}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch {
					case strings.HasSuffix(r.URL.Path, "/info"):
						if tt.infoResponse == "" {
							w.WriteHeader(http.StatusNotFound)
							return
						}
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(tt.infoResponse))
					case isApplianceRootPath(r.URL.Path):
						if tt.rootResponse == "" {
							w.WriteHeader(http.StatusNotFound)
							return
						}
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(tt.rootResponse))
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				t.Cleanup(server.Close)

				applianceURL := strings.TrimSuffix(server.URL, "/") + "/api"
				config := Config{ApplianceURL: applianceURL}
				assert.Equalf(t, tt.want, defaultEnvironment(config, false), "defaultEnvironment(%v)", applianceURL)
			})
		}
	})

	t.Run("applyDefaults does not infer environment without appliance URL", func(t *testing.T) {
		config := Config{}
		config.applyDefaults(false)
		assert.Empty(t, config.Environment)
	})

	t.Run("applyDefaults does not re-probe when Environment is already set", func(t *testing.T) {
		requests := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			if strings.HasSuffix(r.URL.Path, "/info") {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(mockEnterpriseInfo))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		t.Cleanup(server.Close)

		applianceURL := strings.TrimSuffix(server.URL, "/") + "/api"
		config := Config{ApplianceURL: applianceURL, Account: "myacct"}

		config.applyDefaults(false)
		assert.Equal(t, EnvironmentSH, config.Environment)
		assert.Equal(t, 1, requests)

		config.applyDefaults(false)
		assert.Equal(t, 1, requests)
	})

	t.Run("applyDefaults persistence", func(t *testing.T) {
		t.Run("confident Edge probe persists environment", func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			}))
			t.Cleanup(server.Close)

			conjurrc := filepath.Join(t.TempDir(), ".conjurrc")
			t.Setenv("CONJURRC", conjurrc)
			require.NoError(t, os.WriteFile(conjurrc, []byte("account: myacct\n"), 0o600))

			applianceURL := strings.TrimSuffix(server.URL, "/") + "/api"
			config := Config{ApplianceURL: applianceURL, Account: "myacct"}
			config.applyDefaults(true)

			data, err := os.ReadFile(conjurrc)
			require.NoError(t, err)
			assert.Contains(t, string(data), "environment: saas")
			assert.Equal(t, EnvironmentSaaS, config.Environment)
		})

		t.Run("inconclusive probe does not persist environment", func(t *testing.T) {
			conjurrc := filepath.Join(t.TempDir(), ".conjurrc")
			t.Setenv("CONJURRC", conjurrc)
			require.NoError(t, os.WriteFile(conjurrc, []byte("account: myacct\n"), 0o600))

			config := Config{
				ApplianceURL: "http://127.0.0.1:1/api",
				Account:      "myacct",
			}
			config.applyDefaults(true)

			data, err := os.ReadFile(conjurrc)
			require.NoError(t, err)
			assert.NotContains(t, string(data), "environment:")
			assert.Equal(t, EnvironmentSaaS, config.Environment)
		})
	})

	t.Run("probe uses short timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(environmentProbeTimeout + time.Second)
		}))
		t.Cleanup(server.Close)

		start := time.Now()
		config := Config{ApplianceURL: strings.TrimSuffix(server.URL, "/") + "/api"}
		env, persistable := resolveDefaultEnvironment(config, false)
		elapsed := time.Since(start)

		assert.Equal(t, EnvironmentSaaS, env)
		assert.False(t, persistable)
		assert.Less(t, elapsed, 2*environmentProbeTimeout+time.Second)
	})
}

func Test_hasAPIBasePath(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{{
		url:  "https://edge.customer.example.com/api",
		want: true,
	}, {
		url:  "https://edge.customer.example.com/api/",
		want: true,
	}, {
		url:  "https://conjur.example.com",
		want: false,
	}, {
		url:  "https://conjur.example.com/api/v1",
		want: false,
	}}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			assert.Equal(t, tt.want, hasAPIBasePath(tt.url))
		})
	}
}

func isApplianceRootPath(path string) bool {
	trimmed := strings.TrimSuffix(path, "/")
	return trimmed == "" || strings.HasSuffix(trimmed, "/api") || strings.HasSuffix(trimmed, "/api/.")
}

func TestImplicitEnvironmentSetting_Integration(t *testing.T) {
	applianceURL := os.Getenv("CONJUR_APPLIANCE_URL")
	if applianceURL == "" {
		t.Skip("CONJUR_APPLIANCE_URL is not set")
	}

	account := os.Getenv("CONJUR_ACCOUNT")
	if account == "" {
		t.Skip("CONJUR_ACCOUNT is not set")
	}

	t.Setenv("CONJUR_ENVIRONMENT", "")

	config := Config{
		ApplianceURL: applianceURL,
		Account:      account,
	}
	require.NoError(t, config.Validate())

	if isConjurCloudURL(applianceURL) {
		assert.Equal(t, EnvironmentSaaS, config.Environment, "Cloud URL should default to saas")
		assert.True(t, config.IsSaaS())
		return
	}

	assert.Equal(t, EnvironmentSH, config.Environment, "Self-hosted URL should default to self-hosted")
	assert.True(t, config.IsSelfHosted())
}

func Test_environmentIsSupported(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"", false},
		{"cloud", false},
		{"saas", true},
		{"CC", false},
		{"enterprise", false},
		{"self-hosted", true},
		{"CE", false},
		{"oss", true},
		{"OSS", true},
		{"open-source", false},
		{"invalid", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, environmentIsSupported(tt.name), "environmentIsSupported(%v)", tt.name)
		})
	}
}

func TestEnvironmentType_FullName(t *testing.T) {
	tests := []struct {
		name string
		e    EnvironmentType
		want string
	}{{
		"Empty",
		EnvironmentType(""),
		"Unknown Environment",
	}, {
		name: "Cloud",
		e:    EnvironmentSaaS,
		want: "Idira Secrets Manager, SaaS",
	}, {
		name: "Enterprise",
		e:    EnvironmentSH,
		want: "Idira Secrets Manager, Self-Hosted",
	}, {
		name: "OSS",
		e:    EnvironmentOSS,
		want: "Conjur Open Source",
	}, {
		name: "SaaS",
		e:    EnvironmentSaaS,
		want: "Idira Secrets Manager, SaaS",
	}, {
		name: "Self-Hosted",
		e:    EnvironmentSH,
		want: "Idira Secrets Manager, Self-Hosted",
	}, {
		name: "Unknown",
		e:    EnvironmentType("unknown"),
		want: "Unknown Environment",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, tt.e.FullName(), "FullName()")
		})
	}
}
