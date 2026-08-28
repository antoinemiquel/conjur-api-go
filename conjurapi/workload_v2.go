package conjurapi

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

type AuthnDescriptorData struct {
	Claims map[string]string `json:"claims,omitempty"`
}

type AuthnDescriptor struct {
	Type      string               `json:"type"`
	ServiceID string               `json:"service_id,omitempty"`
	Data      *AuthnDescriptorData `json:"data,omitempty"`
}

type Workload struct {
	Name             string            `json:"name"`
	Branch           string            `json:"branch"`
	Type             string            `json:"type,omitempty"`
	Owner            *Owner            `json:"owner,omitempty"`
	Annotations      map[string]string `json:"annotations,omitempty"`
	AuthnDescriptors []AuthnDescriptor `json:"authn_descriptors"`
	RestrictedTo     []string          `json:"restricted_to,omitempty"`
}

func (c *ClientV2) CreateWorkload(workload Workload) ([]byte, error) {
	if !c.config.IsSaaS() {
		return nil, fmt.Errorf(NotSupportedInConjurEnterprise, "Workload API")
	}

	req, err := c.CreateWorkloadRequest(workload)
	if err != nil {
		return nil, err
	}
	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}

func (c *ClientV2) DeleteWorkload(workloadId string) ([]byte, error) {
	if !c.config.IsSaaS() {
		return nil, fmt.Errorf(NotSupportedInConjurEnterprise, "Workload API")
	}

	req, err := c.DeleteWorkloadRequest(workloadId)
	if err != nil {
		return nil, err
	}
	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}

func (c *ClientV2) CreateWorkloadRequest(workload Workload) (*http.Request, error) {
	errors := []string{}

	err := workload.Validate()
	if err != nil {
		return nil, err
	}

	if len(workload.AuthnDescriptors) == 0 {
		errors = append(errors, "Must specify at least one authenticator in authn_descriptors")
	} else {
		for i, d := range workload.AuthnDescriptors {
			if d.Type == "" {
				errors = append(errors, fmt.Sprintf("authn_descriptors[%d] missing type", i))
			}
		}
	}

	if len(errors) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(errors, " -- "))
	}
	// Default type
	if workload.Type == "" {
		workload.Type = "other"
	}

	fullURL := makeRouterURL(c.config.ApplianceURL, "workloads").String()

	return newV2JSONRequest(http.MethodPost, fullURL, workload, v2APIHeaderBeta)
}

func (c *ClientV2) DeleteWorkloadRequest(workloadID string) (*http.Request, error) {
	if workloadID == "" {
		return nil, fmt.Errorf("Must specify a Workload ID")
	}

	fullURL := makeRouterURL(c.config.ApplianceURL, "workloads", url.QueryEscape(workloadID)).String()
	return newV2Request(http.MethodDelete, fullURL, v2APIHeaderBeta)
}

func (w Workload) Validate() error {
	var errs []error
	if w.Branch == "" {
		errs = append(errs, fmt.Errorf("Missing required attribute Workload Branch"))
	}
	if w.Name == "" {
		errs = append(errs, fmt.Errorf("Missing required attribute Workload Name"))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
