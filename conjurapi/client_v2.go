package conjurapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

const MinVersion = "1.23.0"
const NotSupportedInConjurCloud = "%s is not supported in Idira Secrets Manager, SaaS"
const NotSupportedInConjurEnterprise = "%s is not supported in Idira Secrets Manager/Conjur OSS"
const NotSupportedInOldVersions = "%s is not supported in Idira Secrets Manager versions older than %s"

// API name labels used in SaaS-support error messages.
const (
	workloadAPIName             = "Workload API"
	issueAPIName                = "Issue API"
	staticSecretAPIName         = "StaticSecret API"
	batchRetrieveSecretsAPIName = "V2 Batch Retrieve Secrets API"
)

type ClientV2 struct {
	*Client
}

// requireSaaS returns an error naming apiName if the client is not
// configured against a SaaS appliance.
func (c *ClientV2) requireSaaS(apiName string) error {
	if !c.config.IsSaaS() {
		return fmt.Errorf(NotSupportedInConjurEnterprise, apiName)
	}
	return nil
}

// submitAndUnmarshal submits req and unmarshals the JSON response body into T.
func submitAndUnmarshal[T any](c *ClientV2, req *http.Request) (*T, error) {
	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	var parsedResp T
	if err := response.JSONResponse(resp, &parsedResp); err != nil {
		return nil, err
	}
	return &parsedResp, nil
}

// submitAndReadData submits req and returns the raw response body, for routes
// whose payload the caller wants unparsed.
func submitAndReadData(c *ClientV2, req *http.Request) ([]byte, error) {
	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}

// newV2Request builds a bodiless HTTP request for a v2 API route.
func newV2Request(method, requestURL, acceptHeader string) (*http.Request, error) {
	request, err := http.NewRequest(method, requestURL, nil)
	if err != nil {
		return nil, err
	}

	request.Header.Add(v2APIOutgoingHeaderID, acceptHeader)
	return request, nil
}

// newV2JSONRequest builds an HTTP request with a JSON-encoded body for a v2
// API route.
func newV2JSONRequest(method, requestURL string, payload any, acceptHeader string) (*http.Request, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest(method, requestURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	request.Header.Add("Content-Type", "application/json")
	request.Header.Add(v2APIOutgoingHeaderID, acceptHeader)
	return request, nil
}
