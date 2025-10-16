package scope

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
)

type Client struct {
	scopesClient *scopes.Client
}

func NewClient(client *api.Client) *Client {
	return &Client{
		scopesClient: scopes.NewClient(client),
	}
}

func (c *Client) ListOrgScopes() ([]ScopeInfo, error) {
	result, err := c.scopesClient.List(context.Background(), "global", scopes.WithRecursive(true))
	if err != nil {
		return nil, fmt.Errorf("error listing scopes: %v", err)
	}

	var orgScopes []ScopeInfo
	for _, scope := range result.Items {
		if scope.Type == "org" {
			orgScopes = append(orgScopes, ScopeInfo{
				ID:          scope.Id,
				Name:        scope.Name,
				Description: scope.Description,
				Type:        scope.Type,
			})
		}
	}

	return orgScopes, nil
}

func (c *Client) ListProjectsInOrg(orgID string) ([]ScopeInfo, error) {
	result, err := c.scopesClient.List(context.Background(), orgID)
	if err != nil {
		return nil, fmt.Errorf("error listing projects: %v", err)
	}

	var projects []ScopeInfo
	for _, scope := range result.Items {
		if scope.Type == "project" {
			projects = append(projects, ScopeInfo{
				ID:          scope.Id,
				Name:        scope.Name,
				Description: scope.Description,
				Type:        scope.Type,
			})
		}
	}

	return projects, nil
}
