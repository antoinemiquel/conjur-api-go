package conjurapi

import (
	"fmt"
	"net/http"
)

const v2APIHeaderBeta string = "application/x.secretsmgr.v2beta+json"
const v2APIHeader string = "application/x.secretsmgr.v2+json"
const v2APIOutgoingHeaderID string = "Accept"
const v2APIIncomingHeaderID string = "Content-Type"

func (c *ClientV2) CreateAuthenticatorRequest(authenticator *AuthenticatorBase) (*http.Request, error) {
	request, err := newV2JSONRequest(http.MethodPost, c.authenticatorsURL("", ""), authenticator, v2APIHeaderBeta)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal authenticator request: %w", err)
	}
	return request, nil
}

func (c *ClientV2) GetAuthenticatorRequest(authenticatorType string, serviceID string) (*http.Request, error) {
	return newV2Request(http.MethodGet, c.authenticatorsURL(authenticatorType, serviceID), v2APIHeaderBeta)
}

func (c *ClientV2) UpdateAuthenticatorRequest(authenticatorType string, serviceID string, enabled bool) (*http.Request, error) {
	request, err := newV2JSONRequest(
		http.MethodPatch,
		c.authenticatorsURL(authenticatorType, serviceID),
		map[string]bool{"enabled": enabled},
		v2APIHeaderBeta,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal authenticator update request: %w", err)
	}
	return request, nil
}

func (c *ClientV2) DeleteAuthenticatorRequest(authenticatorType string, serviceID string) (*http.Request, error) {
	return newV2Request(http.MethodDelete, c.authenticatorsURL(authenticatorType, serviceID), v2APIHeaderBeta)
}

func (c *ClientV2) ListAuthenticatorsRequest() (*http.Request, error) {
	return newV2Request(http.MethodGet, c.authenticatorsURL("", ""), v2APIHeaderBeta)
}

func (c *ClientV2) authenticatorsURL(authenticatorType string, serviceID string) string {
	// If running against Secrets Manager SaaS, the account is not used in the URL.
	account := c.config.Account
	if c.config.IsSaaS() {
		account = ""
	}

	// TODO: validate GCP does not use service IDs and if it should be accessible via this API
	if authenticatorType == "gcp" {
		return makeRouterURL(c.config.ApplianceURL, "authenticators", account, authenticatorType).String()
	}

	if authenticatorType != "" && authenticatorType != "authn" {
		return makeRouterURL(c.config.ApplianceURL, "authenticators", account, authenticatorType, serviceID).String()
	}

	// For the default authenticators service endpoint
	return makeRouterURL(c.config.ApplianceURL, "authenticators", account).String()
}
