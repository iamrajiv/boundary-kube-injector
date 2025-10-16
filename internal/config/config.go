package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

func Load() Config {
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
