package conjurapi

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/cyberark/conjur-api-go/conjurapi/response"
)

type GroupMember struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

func (c *ClientV2) AddGroupMember(groupID string, member GroupMember) (*GroupMember, error) {
	memberResp := GroupMember{}

	if !c.config.IsSaaS() && c.VerifyMinServerVersion(MinVersion) != nil {
		return nil, fmt.Errorf(NotSupportedInOldVersions, "Group Membership API", MinVersion)
	}

	req, err := c.AddGroupMemberRequest(groupID, member)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return &memberResp, response.JSONResponse(resp, &memberResp)
}

func (c *ClientV2) RemoveGroupMember(groupID string, member GroupMember) ([]byte, error) {
	if !c.config.IsSaaS() && c.VerifyMinServerVersion(MinVersion) != nil {
		return nil, fmt.Errorf(NotSupportedInOldVersions, "Group Membership API", MinVersion)
	}

	req, err := c.RemoveGroupMemberRequest(groupID, member)
	if err != nil {
		return nil, err
	}

	resp, err := c.SubmitRequest(req)
	if err != nil {
		return nil, err
	}

	return response.DataResponse(resp)
}

func (c *ClientV2) AddGroupMemberRequest(groupID string, member GroupMember) (*http.Request, error) {
	if groupID == "" {
		return nil, fmt.Errorf("Must specify a Group ID")
	}

	err := member.Validate()
	if err != nil {
		return nil, err
	}

	req, err := newV2JSONRequest(http.MethodPost, c.addGroupMembershipURL(groupID), member, v2APIHeaderBeta)
	if err != nil {
		return nil, fmt.Errorf("Failed to create add group member request: %w", err)
	}

	return req, nil
}

func (c *ClientV2) RemoveGroupMemberRequest(groupID string, member GroupMember) (*http.Request, error) {
	if groupID == "" {
		return nil, fmt.Errorf("Must specify a Group ID")
	}
	err := member.Validate()
	if err != nil {
		return nil, err
	}

	req, err := newV2Request(http.MethodDelete, c.removeGroupMembershipURL(groupID, member), v2APIHeaderBeta)
	if err != nil {
		return nil, fmt.Errorf("Failed to create remove group member request: %v", err)
	}

	return req, nil
}

func (member GroupMember) Validate() error {
	var errs []error
	if member.ID == "" || member.Kind == "" {
		errs = append(errs, fmt.Errorf("Must specify a Member"))
	}

	switch member.Kind {
	case "user", "host", "group":
	default:
		errs = append(errs, fmt.Errorf("Invalid member kind: %v", member.Kind))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (c *ClientV2) addGroupMembershipURL(groupID string) string {
	account := c.config.Account
	if c.config.IsSaaS() {
		account = ""
	}
	return makeRouterURL(c.config.ApplianceURL, "groups", account, groupID, "members").String()
}

func (c *ClientV2) removeGroupMembershipURL(groupID string, member GroupMember) string {
	account := c.config.Account
	if c.config.IsSaaS() {
		account = ""
	}
	return makeRouterURL(c.config.ApplianceURL, "groups", account, groupID, "members", member.Kind, member.ID).String()
}
