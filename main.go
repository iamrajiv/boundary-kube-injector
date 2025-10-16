package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/AlecAivazis/survey/v2"
	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/joho/godotenv"
)

type Config struct {
	BoundaryAddr string
	LoginName    string
	AuthMethodID string
	Password     string
}

type SessionData struct {
	Port        int `json:"port"`
	Credentials []struct {
		CredentialSource struct {
			Name string `json:"name"`
		} `json:"credential_source"`
		Secret struct {
			Decoded struct {
				ServiceAccountToken string `json:"service_account_token"`
				Data                struct {
					CaCrt string `json:"ca_crt"`
				} `json:"data"`
			} `json:"decoded"`
		} `json:"secret"`
	} `json:"credentials"`
}

func loadConfig() Config {
	// Load .env file
	err := godotenv.Load()
	if err != nil {
		fmt.Printf("Error loading .env file: %v\n", err)
		os.Exit(1)
	}

	config := Config{
		BoundaryAddr: os.Getenv("BOUNDARY_ADDR"),
		LoginName:    os.Getenv("BOUNDARY_LOGIN_NAME"),
		AuthMethodID: os.Getenv("BOUNDARY_AUTH_METHOD_ID"),
		Password:     os.Getenv("BOUNDARY_PASSWORD"),
	}

	// Validate required fields
	if config.BoundaryAddr == "" || config.AuthMethodID == "" ||
		config.LoginName == "" || config.Password == "" {
		fmt.Println("Error: All environment variables must be set in .env file")
		fmt.Println("Required variables:")
		fmt.Println("- BOUNDARY_ADDR")
		fmt.Println("- BOUNDARY_LOGIN_NAME")
		fmt.Println("- BOUNDARY_AUTH_METHOD_ID")
		fmt.Println("- BOUNDARY_PASSWORD")
		os.Exit(1)
	}

	return config
}

func getConfig() Config {
	config := Config{}

	// Available auth methods
	authMethods := []string{"password", "oidc", "jwt", "ldap"}

	prompts := []*survey.Question{
		{
			Name: "boundaryAddr",
			Prompt: &survey.Input{
				Message: "Enter Boundary address:",
				Default: "http://localhost:9200",
			},
		},
		{
			Name: "authMethodID",
			Prompt: &survey.Input{
				Message: "Enter auth method ID:",
			},
		},
		{
			Name: "authMethod",
			Prompt: &survey.Select{
				Message: "Select authentication method:",
				Options: authMethods,
				Default: "password",
			},
		},
		{
			Name: "username",
			Prompt: &survey.Input{
				Message: "Enter username:",
			},
		},
		{
			Name: "password",
			Prompt: &survey.Password{
				Message: "Enter password:",
			},
		},
	}

	survey.Ask(prompts, &config)
	return config
}

func authenticateWithBoundary(config Config) *api.Client {
	client, err := api.NewClient(&api.Config{
		Addr: config.BoundaryAddr,
	})
	if err != nil {
		fmt.Printf("Error creating client: %v\n", err)
		os.Exit(1)
	}

	amClient := authmethods.NewClient(client)
	credentials := map[string]interface{}{
		"login_name": config.LoginName,
		"password":   config.Password,
	}

	authenticationResult, err := amClient.Authenticate(context.Background(), config.AuthMethodID, "login", credentials)
	if err != nil {
		fmt.Printf("Error authenticating: %v\n", err)
		os.Exit(1)
	}

	client.SetToken(fmt.Sprint(authenticationResult.Attributes["token"]))
	return client
}

// ScopeInfo contains information about a Boundary scope
type ScopeInfo struct {
	ID          string
	Name        string
	Description string
	Type        string
}

// TargetInfo contains information about a Boundary target
type TargetInfo struct {
	ID          string
	Name        string
	Description string
	Type        string
}

// printScopes prints the scopes in a table format
func printScopes(scopes []ScopeInfo, scopeType string) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	fmt.Printf("\n%s Scopes:\n", scopeType)
	fmt.Fprintln(w, "ID\tName\tDescription")
	for _, scope := range scopes {
		fmt.Fprintf(w, "%s\t%s\t%s\n", scope.ID, scope.Name, scope.Description)
	}
}

// printTargets prints the targets in a table format
func printTargets(targets []TargetInfo) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	fmt.Println("\nTargets:")
	fmt.Fprintln(w, "ID\tName\tDescription")
	for _, target := range targets {
		fmt.Fprintf(w, "%s\t%s\t%s\n", target.ID, target.Name, target.Description)
	}
}

// listOrgScopes fetches and displays organization scopes
func listOrgScopes(client *scopes.Client) ([]ScopeInfo, error) {
	result, err := client.List(context.Background(), "global", scopes.WithRecursive(true))
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

// listProjectsInOrg fetches and displays projects within selected org
func listProjectsInOrg(client *scopes.Client, orgID string) ([]ScopeInfo, error) {
	result, err := client.List(context.Background(), orgID)
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

// listTargetsInProject fetches and displays targets within selected project
func listTargetsInProject(client *scopes.Client, projectID string) ([]TargetInfo, error) {
	result, err := client.List(context.Background(), projectID)
	if err != nil {
		return nil, fmt.Errorf("error listing targets: %v", err)
	}

	var targets []TargetInfo
	for _, target := range result.Items {
		if target.Type == "target" {
			targets = append(targets, TargetInfo{
				ID:          target.Id,
				Name:        target.Name,
				Description: target.Description,
				Type:        target.Type,
			})
		}
	}

	return targets, nil
}

// selectOrgScope prompts user to select an org scope
func selectOrgScope(orgScopes []ScopeInfo) (string, error) {
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

	err := survey.AskOne(prompt, &selected)
	if err != nil {
		return "", err
	}

	return scopeMap[selected], nil
}

// selectedProjectID returns the selected project ID
func selectedProjectID(projects []ScopeInfo) (string, error) {
	if len(projects) == 0 {
		return "", fmt.Errorf("no projects found")
	}

	var options []string
	scopeMap := make(map[string]string)

	for _, project := range projects {
		option := fmt.Sprintf("%s (%s)", project.Name, project.ID)
		options = append(options, option)
		scopeMap[option] = project.ID
	}

	var selected string
	prompt := &survey.Select{
		Message: "Select a project scope:",
		Options: options,
	}

	err := survey.AskOne(prompt, &selected)
	if err != nil {
		return "", err
	}

	fmt.Println("Selected project ID: ", scopeMap[selected])
	return scopeMap[selected], nil
}

// listAndPrintScopes handles the interactive scope listing process
func listAndPrintScopes(client *scopes.Client) error {
	// First, list and print org scopes
	orgScopes, err := listOrgScopes(client)
	if err != nil {
		return fmt.Errorf("error listing org scopes: %v", err)
	}

	// Print organization scopes
	printScopes(orgScopes, "Organization")

	// Prompt user to select an org scope
	selectedOrgID, err := selectOrgScope(orgScopes)
	if err != nil {
		return fmt.Errorf("error selecting org scope: %v", err)
	}

	// List and print projects in selected org
	projects, err := listProjectsInOrg(client, selectedOrgID)
	if err != nil {
		return fmt.Errorf("error listing projects: %v", err)
	}

	// Print projects in selected org
	printScopes(projects, "Project")

	// Prompt user to select an project scope
	selectedProjectID, err := selectedProjectID(projects)
	if err != nil {
		return fmt.Errorf("error selecting project scope: %v", err)
	}

	// List and print targets in selected project
	targets, err := listTargetsInProject(client, selectedProjectID)
	if err != nil {
		return fmt.Errorf("error listing targets: %v", err)
	}

	// Print targets in selected project
	printTargets(targets)

	return nil
}

func main() {
	config := loadConfig()
	client := authenticateWithBoundary(config)

	// List all scopes and print them in a table format
	err := listAndPrintScopes(scopes.NewClient(client))
	if err != nil {
		fmt.Printf("Error listing scopes: %v\n", err)
		os.Exit(1)
	}
}
