package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"github.com/luikyv/go-oidc/examples/authutil"
	"golang.org/x/oauth2"
)

// run this against examples/device

func main() {
	// NOTE: only for testing
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	issuer := authutil.Issuer

	config := oauth2.Config{
		ClientID: "client_one",
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: issuer + "/device_authorization",
			TokenURL:      issuer + "/token",
		},
	}

	ctx := context.Background()
	response, err := config.DeviceAuth(ctx)
	if err != nil {
		log.Fatalf("failed to start device authorization: %v", err)
	}

	if response.VerificationURIComplete != "" {
		fmt.Printf("please open the following link: %s\n", response.VerificationURIComplete)
	} else {
		fmt.Printf("please enter code %s at %s\n", response.UserCode, response.VerificationURI)
	}

	token, err := config.DeviceAccessToken(ctx, response)
	if err != nil {
		log.Fatalf("failed to get token: %v", err)
	}
	fmt.Println(token)
}
