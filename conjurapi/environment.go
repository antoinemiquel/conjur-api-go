package conjurapi

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/cyberark/conjur-api-go/conjurapi/logging"
)

const environmentProbeTimeout = 5 * time.Second

type environmentProbeResult struct {
	environment EnvironmentType
	persistable bool
}

// EnvironmentType represents the type of Secrets Manager environment.
type EnvironmentType string

const (
	// EnvironmentSaaS represents the Idira Secrets Manager, SaaS environment.
	EnvironmentSaaS EnvironmentType = "saas"
	// EnvironmentSH represents the Idira Secrets Manager, Self-Hosted environment.
	EnvironmentSH EnvironmentType = "self-hosted"
	// EnvironmentOSS represents the Conjur Open Source environment.
	EnvironmentOSS EnvironmentType = "oss"
)

// SupportedEnvironments lists all supported environment types.
var SupportedEnvironments = []string{string(EnvironmentSaaS), string(EnvironmentSH), string(EnvironmentOSS)}

// String returns the string representation of the EnvironmentType.
func (e *EnvironmentType) String() string {
	return string(*e)
}

// FullName returns the full descriptive name of the EnvironmentType.
func (e *EnvironmentType) FullName() string {
	switch *e {
	case EnvironmentSaaS:
		return "Idira Secrets Manager, SaaS"
	case EnvironmentSH:
		return "Idira Secrets Manager, Self-Hosted"
	case EnvironmentOSS:
		return "Conjur Open Source"
	default:
		return "Unknown Environment"
	}
}

// Set sets the EnvironmentType based on the provided string value.
func (e *EnvironmentType) Set(value string) error {
	switch value {
	case string(EnvironmentSH), "CE", "enterprise":
		*e = EnvironmentSH
	case string(EnvironmentOSS), "OSS", "open-source":
		*e = EnvironmentOSS
	case string(EnvironmentSaaS), "cloud", "CC":
		*e = EnvironmentSaaS
	default:
		return fmt.Errorf("invalid value environment: %s, allowed values %v", value, SupportedEnvironments)
	}
	return nil
}

// Type returns the type of the EnvironmentType for flag parsing.
func (e *EnvironmentType) Type() string {
	return "string"
}

func environmentIsSupported(environment string) bool {
	return slices.Contains(SupportedEnvironments, strings.ToLower(environment))
}

func defaultEnvironment(config Config, showLog bool) EnvironmentType {
	env, _ := resolveDefaultEnvironment(config, showLog)
	return env
}

func resolveDefaultEnvironment(config Config, showLog bool) (EnvironmentType, bool) {
	url := config.ApplianceURL
	if isConjurCloudURL(url) {
		if showLog {
			logging.ApiLog.Info("Detected Idira Secrets Manager, SaaS URL, setting 'Environment' to 'saas'")
		}
		return EnvironmentSaaS, true
	}
	if hasAPIBasePath(url) {
		result := probeEnvironmentFromAppliance(config, showLog)
		if showLog {
			logging.ApiLog.Infof(
				"Probed appliance with '/api' base path, setting 'Environment' to '%s'",
				result.environment,
			)
		}
		return result.environment, result.persistable
	}
	if showLog {
		logging.ApiLog.Info("'Environment' not specified, setting to 'self-hosted'")
	}
	return EnvironmentSH, true
}

func probeEnvironmentFromAppliance(config Config, showLog bool) environmentProbeResult {
	if showLog {
		logging.ApiLog.Info(
			"Ambiguous '/api' base path; probing appliance '/info' and root endpoints to detect environment. " +
				"Set CONJUR_ENVIRONMENT to skip this probe.",
		)
	}

	result := environmentProbeResult{
		environment: EnvironmentSaaS,
		persistable: false,
	}

	httpClient, err := createProbeHttpClient(config)
	if err != nil {
		logging.ApiLog.Warningf(
			"Could not create HTTP client for environment probe: %s; defaulting 'Environment' to 'saas' without persisting",
			err,
		)
		return result
	}

	client := &Client{config: config, httpClient: httpClient}
	hasSurface, confident := client.classifySelfHostedSurface()
	if !confident {
		logging.ApiLog.Warning(
			"Environment probe could not reach the appliance; defaulting 'Environment' to 'saas' without persisting",
		)
		return result
	}

	if hasSurface {
		return environmentProbeResult{
			environment: EnvironmentSH,
			persistable: true,
		}
	}

	return environmentProbeResult{
		environment: EnvironmentSaaS,
		persistable: true,
	}
}

func createProbeHttpClient(config Config) (*http.Client, error) {
	httpClient, err := createHttpClient(config)
	if err != nil {
		return nil, err
	}
	httpClient.Timeout = environmentProbeTimeout
	return httpClient, nil
}

// hasAPIBasePath reports whether the base URL's path ends with '/api'. Both Edge
// deployments and on-prem nginx mounts can use this suffix, so it is only an
// ambiguity signal and not sufficient on its own to classify the environment.
func hasAPIBasePath(baseURL string) bool {
	return strings.HasSuffix(strings.TrimSuffix(baseURL, "/"), "/api")
}
