package cli

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/boundary-kube-injector/internal/printer"
	"github.com/boundary-kube-injector/internal/scope"
)

type Handler struct {
	scopeClient *scope.Client
	printer     *printer.Printer
}

func NewHandler(scopeClient *scope.Client) *Handler {
	return &Handler{
		scopeClient: scopeClient,
		printer:     printer.New(),
	}
}

func (h *Handler) Run() error {
	// List org scopes
	orgScopes, err := h.scopeClient.ListOrgScopes()
	if err != nil {
		return fmt.Errorf("error listing org scopes: %v", err)
	}

	// Print organization scopes
	h.printer.PrintScopes(orgScopes, "Organization")

	// Select org scope
	selectedOrgID, err := h.selectOrgScope(orgScopes)
	if err != nil {
		return fmt.Errorf("error selecting org scope: %v", err)
	}

	// List and print projects
	projects, err := h.scopeClient.ListProjectsInOrg(selectedOrgID)
	if err != nil {
		return fmt.Errorf("error listing projects: %v", err)
	}

	h.printer.PrintScopes(projects, "Project")
	return nil
}

func (h *Handler) selectOrgScope(orgScopes []scope.ScopeInfo) (string, error) {
	if len(orgScopes) == 0 {
		return "", fmt.Errorf("no organization scopes found")
	}

	var options []string
	scopeMap := make(map[string]string)

	for _, scope := range orgScopes {
		option := fmt.Sprintf("%s (%s)", scope.Name, scope.ID)
		options = append(options, option)
		scopeMap[option] = scope.ID
	}

	var selected string
	prompt := &survey.Select{
		Message: "Select an organization scope:",
		Options: options,
	}

	if err := survey.AskOne(prompt, &selected); err != nil {
		return "", err
	}

	return scopeMap[selected], nil
}
