package clientutil

import "github.com/luikyv/go-oidc/pkg/goidc"

var ErrClientNotIdentified = goidc.NewError(goidc.ErrorCodeInvalidClient,
	"could not identify the client")
