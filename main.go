package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/api/targets"
	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

// Types
// ----------------------------------------

type Config struct {
	BoundaryAddr string
	LoginName    string
	AuthMethodID string
	Password     string
}

// CLIConfig holds the command-line flag values
type CLIConfig struct {
	TargetID      string
	TargetAlias   string
	SkipSelection bool
}

type ScopeInfo struct {
	ID          string
	Name        string
	Description string
	Type        string
}

type TargetInfo struct {
	ID          string
	Name        string
	Description string
	Type        string
}

type SessionInfo struct {
	Started  string // Session creation time
	ID       string // Session ID
	Target   string // Target name or ID
	ProxyURL string // Proxy URL for the session
	Status   string // Session status (e.g., active, terminated)
}

type KubeConfig struct {
	APIVersion     string `yaml:"apiVersion"`
	Kind           string `yaml:"kind"`
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			CertificateAuthority     string `yaml:"certificate-authority,omitempty"`
			CertificateAuthorityData string `yaml:"certificate-authority-data,omitempty"`
			Server                   string `yaml:"server"`
			TLSServerName            string `yaml:"tls-server-name,omitempty"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			Token string `yaml:"token,omitempty"`
			Exec  *struct {
				APIVersion string   `yaml:"apiVersion,omitempty"`
				Command    string   `yaml:"command,omitempty"`
				Args       []string `yaml:"args,omitempty"`
				Env        []struct {
					Name  string `yaml:"name"`
					Value string `yaml:"value"`
				} `yaml:"env,omitempty"`
				InteractiveMode    string `yaml:"interactiveMode,omitempty"`
				ProvideClusterInfo bool   `yaml:"provideClusterInfo,omitempty"`
			} `yaml:"exec,omitempty"`
		} `yaml:"user"`
	} `yaml:"users"`
	Preferences map[string]interface{} `yaml:"preferences,omitempty"`
}

// Configuration Management
// ----------------------------------------

func loadConfig() Config {
	if err := godotenv.Load(); err != nil {
		fmt.Printf("Error loading .env file: %v\n", err)
		os.Exit(1)
	}

	config := Config{
		BoundaryAddr: os.Getenv("BOUNDARY_ADDR"),
		LoginName:    os.Getenv("BOUNDARY_LOGIN_NAME"),
		AuthMethodID: os.Getenv("BOUNDARY_AUTH_METHOD_ID"),
		Password:     os.Getenv("BOUNDARY_PASSWORD"),
	}

	validateConfig(config)
	return config
}

func validateConfig(config Config) {
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
}

// Authentication
// ----------------------------------------

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

// Scope Operations
// ----------------------------------------

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

// Target Operations
// ----------------------------------------

func listTargetsInProject(client *api.Client, projectID string) ([]TargetInfo, error) {
	targetClient := targets.NewClient(client)
	result, err := targetClient.List(context.Background(), projectID)
	if err != nil {
		return nil, fmt.Errorf("error listing targets: %v", err)
	}

	var targetList []TargetInfo
	for _, target := range result.Items {
		targetList = append(targetList, TargetInfo{
			ID:          target.Id,
			Name:        target.Name,
			Description: target.Description,
			Type:        target.Type,
		})
	}

	return targetList, nil
}

func getTargetByID(client *api.Client, targetID string) (*targets.Target, error) {
	targetClient := targets.NewClient(client)
	result, err := targetClient.Read(context.Background(), targetID)
	if err != nil {
		return nil, fmt.Errorf("error reading target: %v", err)
	}
	return result.Item, nil
}

func lookupTargetByAlias(client *api.Client, alias string) (string, error) {
	// Start with the global scope
	scopeClient := scopes.NewClient(client)

	// Get all org scopes
	orgs, err := listOrgScopes(scopeClient)
	if err != nil {
		return "", fmt.Errorf("error listing organizations: %v", err)
	}

	// For each org, search in projects
	for _, org := range orgs {
		projects, err := listProjectsInOrg(scopeClient, org.ID)
		if err != nil {
			continue
		}

		// For each project, search targets
		for _, project := range projects {
			targetClient := targets.NewClient(client)
			result, err := targetClient.List(context.Background(), project.ID)
			if err != nil {
				continue
			}

			// Check each target for matching alias or name
			for _, target := range result.Items {
				// Check if the name matches
				if target.Name == alias {
					return target.Id, nil
				}

				// Check if there's an alias attribute
				if target.Attributes != nil {
					attrs := target.Attributes
					if aliasVal, ok := attrs["alias"]; ok && aliasVal == alias {
						return target.Id, nil
					}
				}
			}
		}
	}

	return "", fmt.Errorf("no target found with alias or name %s", alias)
}

func connectToTarget(client *api.Client, targetID string) (*targets.SessionAuthorization, error) {
	targetClient := targets.NewClient(client)
	sessionResult, err := targetClient.AuthorizeSession(context.Background(), targetID)
	if err != nil {
		return nil, fmt.Errorf("error authorizing session: %v", err)
	}
	return sessionResult.Item, nil
}

// Session Operations

func getScopeIDForTarget(client *api.Client, targetID string) (string, error) {
	targetClient := targets.NewClient(client)
	target, err := targetClient.Read(context.Background(), targetID)
	if err != nil {
		return "", fmt.Errorf("error reading target: %v", err)
	}
	return target.Item.ScopeId, nil
}

func listActiveSessions(client *api.Client, scopeID string) ([]SessionInfo, error) {
	sessionClient := sessions.NewClient(client)
	result, err := sessionClient.List(context.Background(), scopeID, sessions.WithRecursive(true))
	if err != nil {
		return nil, fmt.Errorf("error listing sessions: %v", err)
	}

	var sessions []SessionInfo
	for _, session := range result.Items {
		sessions = append(sessions, SessionInfo{
			Started:  session.CreatedTime.Format("2006-01-02 15:04:05"), // Format creation time
			ID:       session.Id,
			Target:   session.TargetId,
			ProxyURL: session.Endpoint,
			Status:   session.Status,
		})
	}

	return sessions, nil
}

// User Interface
// ----------------------------------------

func selectOrgScope(orgScopes []ScopeInfo) (string, error) {
	if len(orgScopes) == 0 {
		return "", fmt.Errorf("no organization scopes found")
	}

	options, scopeMap := buildScopeOptions(orgScopes)
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

func selectedProjectID(projects []ScopeInfo) (string, error) {
	if len(projects) == 0 {
		return "", fmt.Errorf("no projects found")
	}

	options, scopeMap := buildScopeOptions(projects)
	var selected string
	prompt := &survey.Select{
		Message: "Select a project scope:",
		Options: options,
	}

	if err := survey.AskOne(prompt, &selected); err != nil {
		return "", err
	}

	fmt.Println("Selected project ID:", scopeMap[selected])
	return scopeMap[selected], nil
}

func selectTarget(targets []TargetInfo) (string, error) {
	if len(targets) == 0 {
		return "", fmt.Errorf("no targets found")
	}

	options, targetMap := buildTargetOptions(targets)
	var selected string
	prompt := &survey.Select{
		Message: "Select a target:",
		Options: options,
	}

	if err := survey.AskOne(prompt, &selected); err != nil {
		return "", err
	}

	return targetMap[selected], nil
}

// Display Functions
// ----------------------------------------

func printScopes(scopes []ScopeInfo, scopeType string) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	fmt.Printf("\n%s Scopes:\n", scopeType)
	fmt.Fprintln(w, "ID\tName\tDescription")
	for _, scope := range scopes {
		fmt.Fprintf(w, "%s\t%s\t%s\n", scope.ID, scope.Name, scope.Description)
	}
}

func printTargets(targets []TargetInfo) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	fmt.Println("\nTargets:")
	fmt.Fprintln(w, "ID\tName\tDescription")
	for _, target := range targets {
		fmt.Fprintf(w, "%s\t%s\t%s\n", target.ID, target.Name, target.Description)
	}
}

// Helper Functions
// ----------------------------------------

func buildScopeOptions(scopes []ScopeInfo) ([]string, map[string]string) {
	var options []string
	scopeMap := make(map[string]string)

	for _, scope := range scopes {
		option := fmt.Sprintf("%s (%s)", scope.Name, scope.ID)
		options = append(options, option)
		scopeMap[option] = scope.ID
	}

	return options, scopeMap
}

func buildTargetOptions(targets []TargetInfo) ([]string, map[string]string) {
	var options []string
	targetMap := make(map[string]string)

	for _, target := range targets {
		option := fmt.Sprintf("%s (%s)", target.Name, target.ID)
		options = append(options, option)
		targetMap[option] = target.ID
	}

	return options, targetMap
}

func extractSessionInfo(output string) map[string]string {
	info := make(map[string]string)

	// Patterns for various target types
	patterns := map[string]*regexp.Regexp{
		"session_id":    regexp.MustCompile(`Session ID:\s+(s_\w+)`),
		"expiration":    regexp.MustCompile(`Expiration:\s+(.+)`),
		"address":       regexp.MustCompile(`Address:\s+(.+)`),
		"port":          regexp.MustCompile(`Port:\s+(\d+)`),
		"certificate":   regexp.MustCompile(`ca_crt":\s+"([^"]+)"`),
		"access_token":  regexp.MustCompile(`service_account_token":\s+"([^"]+)"`),
		"proxy_port":    regexp.MustCompile(`listening on .*:(\d+)`),
		"proxy_address": regexp.MustCompile(`listening on ([\d.]+:\d+)`),
	}

	for key, re := range patterns {
		matches := re.FindStringSubmatch(output)
		if len(matches) > 1 {
			info[key] = matches[1]
		} else {
			info[key] = "" // Default to empty if not found
		}
	}

	// Log for debugging
	fmt.Printf("Extracted session info: %+v\n", info)
	return info
}

func saveCertificate(certificate, targetID, sessionID string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %v", err)
	}

	// Log raw input for debugging
	fmt.Printf("Raw certificate input: %q\n", certificate)

	// Replace escaped newlines and trim
	certificate = strings.ReplaceAll(certificate, "\\n", "\n")
	certificate = strings.TrimSpace(certificate)

	// Split into lines and remove all BEGIN/END markers
	lines := strings.Split(certificate, "\n")
	var certBody []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.Contains(trimmed, "-----BEGIN") || strings.Contains(trimmed, "-----END") || trimmed == "CERTIFICATE-----" {
			continue // Skip empty lines and any BEGIN/END markers
		}
		certBody = append(certBody, trimmed)
	}

	if len(certBody) == 0 {
		return fmt.Errorf("certificate body is empty after cleaning")
	}

	// Reconstruct with single BEGIN and END, no trailing newline
	cleanedLines := append([]string{"-----BEGIN CERTIFICATE-----"}, certBody...)
	cleanedLines = append(cleanedLines, "-----END CERTIFICATE-----")
	cleanedCert := strings.Join(cleanedLines, "\n")     // Join with newlines
	cleanedCert = strings.TrimSuffix(cleanedCert, "\n") // Remove trailing newline

	// Log the final output for verification
	fmt.Printf("Final cleaned certificate: %q\n", cleanedCert)

	certPath := filepath.Join(homeDir, ".kube", fmt.Sprintf("boundary_%s_%s.crt", targetID, sessionID))

	if err := os.WriteFile(certPath, []byte(cleanedCert), 0644); err != nil {
		return fmt.Errorf("failed to save certificate to %s: %v", certPath, err)
	}

	fmt.Printf("Certificate successfully saved to: %s\n", certPath)
	return nil
}

func updateKubeConfig(targetID, sessionID, address, port, certificatePath, accessToken, targetName string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("error getting home directory: %v", err)
	}

	configPath := filepath.Join(homeDir, ".kube", "config")
	var existingConfig []byte

	// Read existing config if it exists
	if _, err := os.Stat(configPath); err == nil {
		existingConfig, err = os.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("error reading kube config: %v", err)
		}
	} else {
		// If no config exists, start with a minimal valid structure
		existingConfig = []byte("apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []\npreferences: {}\n")
	}

	// Define the new entries as YAML snippets with consistent structure
	clusterName := targetName
	contextName := fmt.Sprintf("%s-%s", targetName, targetID)
	userName := fmt.Sprintf("user-%s", sessionID)

	newCluster := fmt.Sprintf(`cluster:
    certificate-authority: %s
    server: https://%s:%s
    tls-server-name: kubernetes
    name: %s`, certificatePath, address, port, clusterName)

	newContext := fmt.Sprintf(`context:
    cluster: %s
    user: %s
    name: %s`, clusterName, userName, contextName)

	newUser := fmt.Sprintf(`name: %s
user:
    token: %s`, userName, accessToken)

	// Check for duplicates by parsing into a map
	var configMap map[string]interface{}
	if err := yaml.Unmarshal(existingConfig, &configMap); err != nil {
		return fmt.Errorf("error unmarshaling existing config: %v", err)
	}

	// If duplicates exist, skip adding them
	if clusters, ok := configMap["clusters"].([]interface{}); ok {
		for _, c := range clusters {
			if cm, ok := c.(map[string]interface{}); ok {
				if name, ok := cm["name"].(string); ok && name == clusterName {
					return nil // Skip if cluster already exists
				}
			}
		}
	}
	if contexts, ok := configMap["contexts"].([]interface{}); ok {
		for _, c := range contexts {
			if cm, ok := c.(map[string]interface{}); ok {
				if name, ok := cm["name"].(string); ok && name == contextName {
					return nil // Skip if context already exists
				}
			}
		}
	}
	if users, ok := configMap["users"].([]interface{}); ok {
		for _, u := range users {
			if um, ok := u.(map[string]interface{}); ok {
				if name, ok := um["name"].(string); ok && name == userName {
					return nil // Skip if user already exists
				}
			}
		}
	}

	// Parse the YAML as a node tree
	var root yaml.Node
	if err := yaml.Unmarshal(existingConfig, &root); err != nil {
		return fmt.Errorf("error unmarshaling YAML tree: %v", err)
	}

	// Helper function to append to a sequence node
	appendToSequence := func(nodes []*yaml.Node, sectionName, newEntry string) error {
		for i := 0; i < len(nodes)-1; i += 2 {
			if nodes[i].Kind == yaml.ScalarNode && nodes[i].Value == sectionName {
				if nodes[i+1].Kind == yaml.SequenceNode {
					// Parse the new entry as a YAML node
					var newNode yaml.Node
					if err := yaml.Unmarshal([]byte(newEntry), &newNode); err != nil {
						return fmt.Errorf("error parsing new %s entry: %v", sectionName, err)
					}
					// Append the mapping node (skip the document node wrapper)
					if len(newNode.Content) > 0 && newNode.Content[0].Kind == yaml.MappingNode {
						nodes[i+1].Content = append(nodes[i+1].Content, newNode.Content[0])
					} else {
						return fmt.Errorf("unexpected node structure for %s entry", sectionName)
					}
				}
				break
			}
		}
		return nil
	}

	// Append new entries to the respective sections
	if err := appendToSequence(root.Content[0].Content, "clusters", newCluster); err != nil {
		return err
	}
	if err := appendToSequence(root.Content[0].Content, "contexts", newContext); err != nil {
		return err
	}
	if err := appendToSequence(root.Content[0].Content, "users", newUser); err != nil {
		return err
	}

	// Encode the updated YAML back to a string
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2) // Match Kubernetes config indentation
	if err := encoder.Encode(&root); err != nil {
		return fmt.Errorf("error encoding updated YAML: %v", err)
	}

	// Write the updated config back to the file
	updatedConfig := buf.Bytes()
	if err := os.WriteFile(configPath, updatedConfig, 0644); err != nil {
		return fmt.Errorf("error writing updated kube config: %v", err)
	}

	fmt.Printf("Updated kube config at: %s\n", configPath)
	return nil
}

func runBoundaryConnect(config Config, targetId, targetName string, client *api.Client) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %v", err)
	}

	os.Setenv("BOUNDARY_ADDR", config.BoundaryAddr)
	os.Setenv("BOUNDARY_PASSWORD", config.Password)

	fmt.Println("\nAuthenticating with Boundary CLI...")
	authCmd := exec.Command("boundary", "authenticate", "password",
		"-addr", config.BoundaryAddr,
		"-login-name", config.LoginName,
		"-auth-method-id", config.AuthMethodID,
		"-password", "env://BOUNDARY_PASSWORD")
	authCmd.Stdout = os.Stdout
	authCmd.Stderr = os.Stderr
	if err := authCmd.Run(); err != nil {
		return fmt.Errorf("error during authentication: %v", err)
	}

	time.Sleep(time.Second)

	// Get scope ID for the target
	scopeID, err := getScopeIDForTarget(client, targetId)
	if err != nil {
		return fmt.Errorf("error getting scope ID: %v", err)
	}

	// List active sessions
	sessionClient := sessions.NewClient(client)
	result, err := sessionClient.List(context.Background(), scopeID, sessions.WithRecursive(true))
	if err != nil {
		return fmt.Errorf("error listing sessions: %v", err)
	}

	var sessions []SessionInfo
	for _, session := range result.Items {
		sessions = append(sessions, SessionInfo{
			Started:  session.CreatedTime.Format("2006-01-02 15:04:05"),
			ID:       session.Id,
			Target:   session.TargetId,
			ProxyURL: session.Endpoint,
			Status:   session.Status,
		})
	}

	var selectedSessionID string
	if len(sessions) > 0 {
		var options []string
		sessionMap := make(map[string]string)
		options = append(options, "Create New Session")
		for _, session := range sessions {
			option := fmt.Sprintf("Session ID: %s (Status: %s, Target: %s)", session.ID, session.Status, session.Target)
			options = append(options, option)
			sessionMap[option] = session.ID
		}

		prompt := &survey.Select{
			Message: "Select an active session or create a new one:",
			Options: options,
		}
		var selected string
		if err := survey.AskOne(prompt, &selected); err != nil {
			return fmt.Errorf("error selecting session: %v", err)
		}

		if selected != "Create New Session" {
			selectedSessionID = sessionMap[selected]
			for _, session := range sessions {
				if session.ID == selectedSessionID {
					fmt.Printf("\nReconnecting to session: %s\n", selectedSessionID)
					w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
					fmt.Fprintln(w, "Started\tSession ID\tTarget\tProxy URL\tStatus")
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", session.Started, session.ID, session.Target, session.ProxyURL, session.Status)
					w.Flush()

					// Reconnect logic (specific to target type)
					cmd := exec.Command("boundary", "connect", "-target-id", targetId)
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					if err := cmd.Run(); err != nil {
						fmt.Printf("Error reconnecting to session: %v\n", err)
					}
					return nil
				}
			}
		}
	}

	// Create new session
	var outputLines []string
	var errorLines []string
	outputChan := make(chan string, 100)
	errorChan := make(chan string, 100)
	doneChan := make(chan bool)

	fmt.Printf("\nStarting boundary connect on target \033[1;33m%s\033[0m\n", targetId)
	connectCmd := exec.Command("boundary", "connect", targetId)

	stdout, err := connectCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("error creating stdout pipe: %v", err)
	}

	stderr, err := connectCmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("error creating stderr pipe: %v", err)
	}

	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			outputLines = append(outputLines, line)
			outputChan <- line
			fmt.Println("Boundary connect stdout:", line)
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("Stdout scanner error: %v\n", err)
		}
		close(outputChan)
		doneChan <- true
	}()

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			errorLines = append(errorLines, line)
			errorChan <- line
			fmt.Println("Boundary connect stderr:", line)
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf("Stderr scanner error: %v\n", err)
		}
		close(errorChan)
	}()

	if err := connectCmd.Start(); err != nil {
		return fmt.Errorf("error starting connect command: %v", err)
	}

	timer := time.NewTimer(5 * time.Second)
	keepReading := true
	for keepReading {
		select {
		case <-timer.C:
			keepReading = false
		case line, ok := <-outputChan:
			if !ok {
				keepReading = false
				break
			}
			if strings.Contains(line, "service_account_token") || strings.Contains(line, "listening on") {
				timer.Reset(2 * time.Second)
			}
		case errLine, ok := <-errorChan:
			if !ok {
				keepReading = false
				break
			}
			if strings.Contains(errLine, "Error") {
				timer.Reset(2 * time.Second)
			}
		case <-doneChan:
			keepReading = false
		}
	}

	if err := connectCmd.Process.Kill(); err != nil {
		fmt.Printf("Warning: error killing connect process: %v\n", err)
	}

	output := strings.Join(outputLines, "\n")
	errorOutput := strings.Join(errorLines, "\n")
	fmt.Printf("Full boundary connect output: %q\n", output)
	fmt.Printf("Full boundary connect error output: %q\n", errorOutput)

	if output == "" && errorOutput != "" {
		fmt.Printf("\nFailed to connect to target %s:\n%s\n", targetId, errorOutput)
		fmt.Println("This target may not be properly configured. Please check its host sources or address in Boundary.")
		return nil
	}

	if output == "" {
		return fmt.Errorf("no output from boundary connect, command may have failed")
	}

	sessionInfo := extractSessionInfo(output)

	fmt.Println("\nSession Information for Target ID:", targetId)
	fmt.Println("----------------------------------------")
	for key, value := range sessionInfo {
		if value != "" {
			fmt.Printf("%s: %s\n", strings.Title(strings.ReplaceAll(key, "_", " ")), value)
		}
	}

	// Handle session info based on available fields
	certPath := filepath.Join(homeDir, ".kube", fmt.Sprintf("boundary_%s_%s.crt", targetId, sessionInfo["session_id"]))
	if sessionInfo["certificate"] != "" {
		if err := saveCertificate(sessionInfo["certificate"], targetId, sessionInfo["session_id"]); err != nil {
			return fmt.Errorf("error saving certificate: %v", err)
		}
	}

	// For Kubernetes-specific targets
	if sessionInfo["access_token"] != "" && sessionInfo["port"] != "" && sessionInfo["certificate"] != "" {
		if err := updateKubeConfig(targetId, sessionInfo["session_id"], sessionInfo["address"], sessionInfo["port"], certPath, sessionInfo["access_token"], targetName); err != nil {
			return fmt.Errorf("error updating kube config: %v", err)
		}
	} else if sessionInfo["proxy_port"] != "" || sessionInfo["port"] != "" {
		// For TCP/SSH targets, just display proxy info
		port := sessionInfo["proxy_port"]
		if port == "" {
			port = sessionInfo["port"]
		}
		address := sessionInfo["address"]
		if address == "" {
			address = "127.0.0.1" // Default for proxy
		}
		fmt.Printf("\nConnect to %s using: %s:%s\n", targetName, address, port)
	} else {
		fmt.Println("No actionable session info available for this target type")
	}

	return nil
}

// Direct connection handler for when a specific target is provided
func handleDirectConnection(client *api.Client, config Config, targetID string) error {
	// Read the target information to show user something
	targetClient := targets.NewClient(client)
	target, err := targetClient.Read(context.Background(), targetID)
	if err != nil {
		fmt.Printf("Error reading target information: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Connecting directly to target: %s (%s)\n", target.Item.Name, targetID)

	// Run the boundary connect with appropriate configuration
	if err := runBoundaryConnect(config, targetID, target.Item.Name, client); err != nil {
		fmt.Printf("Error connecting to target: %v\n", err)
		os.Exit(1)
	}

	return nil
}

// Main Flow
// ----------------------------------------

func listAndPrintScopes(client *api.Client, config Config) error {
	scopeClient := scopes.NewClient(client)

	orgScopes, err := listOrgScopes(scopeClient)
	if err != nil {
		return fmt.Errorf("error listing org scopes: %v", err)
	}
	printScopes(orgScopes, "Organization")

	selectedOrgID, err := selectOrgScope(orgScopes)
	if err != nil {
		return fmt.Errorf("error selecting org scope: %v", err)
	}

	projects, err := listProjectsInOrg(scopeClient, selectedOrgID)
	if err != nil {
		return fmt.Errorf("error listing projects: %v", err)
	}
	printScopes(projects, "Project")

	selectedProjectID, err := selectedProjectID(projects)
	if err != nil {
		return fmt.Errorf("error selecting project scope: %v", err)
	}

	targets, err := listTargetsInProject(client, selectedProjectID)
	if err != nil {
		return fmt.Errorf("error listing targets: %v", err)
	}
	printTargets(targets)

	selectedTargetID, err := selectTarget(targets)
	if err != nil {
		return fmt.Errorf("error selecting target: %v", err)
	}

	// Find target name for the selected target ID
	var targetName string
	for _, t := range targets {
		if t.ID == selectedTargetID {
			targetName = t.Name
			break
		}
	}

	if err := runBoundaryConnect(config, selectedTargetID, targetName, client); err != nil {
		return fmt.Errorf("error running boundary connect: %v", err)
	}

	return nil
}

func main() {
	// Define CLI configuration with flags
	var cliConfig CLIConfig

	// Define command-line flags
	flag.StringVar(&cliConfig.TargetID, "target-id", "", "Direct Boundary target ID to connect to (bypasses selection)")
	flag.StringVar(&cliConfig.TargetAlias, "target-alias", "", "Boundary target alias to connect to (bypasses selection)")
	flag.BoolVar(&cliConfig.SkipSelection, "skip-selection", false, "Skip the interactive selection workflow")
	flag.Parse()

	// Load environment configuration
	config := loadConfig()
	client := authenticateWithBoundary(config)

	// Determine the workflow based on flags
	if cliConfig.TargetID != "" {
		// Direct target ID connection workflow
		fmt.Printf("Using provided target ID: %s\n", cliConfig.TargetID)
		if err := handleDirectConnection(client, config, cliConfig.TargetID); err != nil {
			fmt.Printf("Error connecting to target: %v\n", err)
			os.Exit(1)
		}
	} else if cliConfig.TargetAlias != "" {
		// Target alias lookup workflow
		fmt.Printf("Looking up target by alias: %s\n", cliConfig.TargetAlias)
		targetID, err := lookupTargetByAlias(client, cliConfig.TargetAlias)
		if err != nil {
			fmt.Printf("Error looking up target by alias: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Found target ID: %s for alias: %s\n", targetID, cliConfig.TargetAlias)
		if err := handleDirectConnection(client, config, targetID); err != nil {
			fmt.Printf("Error connecting to target: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Use the existing interactive workflow
		if err := listAndPrintScopes(client, config); err != nil {
			fmt.Printf("Error in interactive workflow: %v\n", err)
			os.Exit(1)
		}
	}
}
