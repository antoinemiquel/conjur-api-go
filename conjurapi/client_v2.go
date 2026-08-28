package conjurapi

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

const MinVersion = "1.23.0"
const NotSupportedInConjurCloud = "%s is not supported in Idira Secrets Manager, SaaS"
const NotSupportedInConjurEnterprise = "%s is not supported in Idira Secrets Manager/Conjur OSS"
const NotSupportedInOldVersions = "%s is not supported in Idira Secrets Manager versions older than %s"

type ClientV2 struct {
	*Client
}

// submitAndUnmarshal submits req and unmarshals the response body's data
// payload into T.
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
