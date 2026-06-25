package util

import (
	"errors"
	"fmt"
	"strings"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type Request struct {
	Scopes    string
	Details   []goidc.AuthDetail
	Resources goidc.Resources
}

// Resolve validates all VC signals (auth details, scopes, resources) for
// internal consistency, then resolves the VC issuer and credential
// configuration IDs.
func Resolve(ctx oidc.Context, req Request) (goidc.VCIssuer, []goidc.VCConfigurationID, error) {
	var issuer goidc.VCIssuer
	credentials := make(map[goidc.VCConfigurationID]struct{})

	if len(ctx.VCIIssuers) == 1 {
		issuer = ctx.VCIIssuers[0]
	}

	if ctx.RAREnabled {
		for _, detail := range req.Details {
			if detail.Type() != goidc.AuthDetailTypeOpenIDCredential {
				continue
			}

			credIDRaw, ok := detail["credential_configuration_id"]
			if !ok {
				return goidc.VCIssuer{}, nil, goidc.WrapError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details",
					fmt.Errorf("credential_configuration_id is required for %s", goidc.AuthDetailTypeOpenIDCredential))
			}
			credID, ok := credIDRaw.(string)
			if !ok {
				return goidc.VCIssuer{}, nil, goidc.WrapError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details",
					fmt.Errorf("credential_configuration_id for %s must be a string", goidc.AuthDetailTypeOpenIDCredential))
			}

			locs := detail.Locations()
			switch len(locs) {
			case 0:
				if len(ctx.VCIIssuers) > 1 {
					return goidc.VCIssuer{}, nil, goidc.WrapError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details",
						errors.New("the credential issuer could not be determined from the authorization details"))
				}
			case 1:
				if issuer.Issuer == "" {
					iss, ok := ctx.VCIssuer(locs[0])
					if !ok {
						return goidc.VCIssuer{}, nil, goidc.WrapError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details",
							errors.New("the authorization detail references an unknown credential issuer"))
					}
					issuer = iss
				}
				if locs[0] != issuer.Issuer {
					return goidc.VCIssuer{}, nil, goidc.WrapError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details",
						errors.New("all openid_credential authorization details must reference the same issuer"))
				}
			default:
				return goidc.VCIssuer{}, nil, goidc.WrapError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details",
					errors.New("openid_credential authorization details must contain at most one location"))
			}

			if _, exists := issuer.Configurations[goidc.VCConfigurationID(credID)]; !exists {
				return goidc.VCIssuer{}, nil, goidc.WrapError(goidc.ErrorCodeInvalidAuthDetails, "invalid authorization details",
					errors.New("the authorization detail references an unknown credential configuration"))
			}

			credentials[goidc.VCConfigurationID(credID)] = struct{}{}
		}
	}

	if req.Scopes != "" {
		for s := range strings.FieldsSeq(req.Scopes) {
			for _, iss := range ctx.VCIIssuers {
				for configID, config := range iss.Configurations {
					if config.Scope.ID != "" && config.Scope.ID == s {
						if issuer.Issuer == "" {
							issuer = iss
						}
						if iss.Issuer != issuer.Issuer {
							return goidc.VCIssuer{}, nil, goidc.WrapError(goidc.ErrorCodeInvalidScope, "invalid scope",
								errors.New("the requested VC scopes resolve to different issuers"))
						}
						credentials[configID] = struct{}{}
					}
				}
			}
		}
	}

	if ctx.ResourceIndicatorsEnabled {
		for _, resource := range req.Resources {
			if iss, ok := ctx.VCIssuer(resource); ok {
				if issuer.Issuer == "" {
					issuer = iss
				}
				if iss.Issuer != issuer.Issuer {
					return goidc.VCIssuer{}, nil, goidc.WrapError(goidc.ErrorCodeInvalidScope, "invalid scope",
						errors.New("the requested VC signals resolve to different issuers"))
				}
			}
		}
	}

	if len(credentials) == 0 {
		return goidc.VCIssuer{}, nil, nil
	}

	configIDs := make([]goidc.VCConfigurationID, 0, len(credentials))
	for id := range credentials {
		configIDs = append(configIDs, id)
	}
	return issuer, configIDs, nil
}
