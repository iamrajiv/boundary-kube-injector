package auth

import (
	"context"
	"fmt"
	"os"

	"github.com/boundary-kube-injector/internal/config"
	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
)

func AuthenticateWithBoundary(config config.Config) *api.Client {
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
