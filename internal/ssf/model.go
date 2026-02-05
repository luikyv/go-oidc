package ssf

import (
	"encoding/json"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	specVersion = "1_0"
)

type Audiences []string

func (auds Audiences) MarshalJSON() ([]byte, error) {
	if len(auds) == 1 {
		return json.Marshal(auds[0])
	}

	return json.Marshal([]string(auds))
}

const (
	jwtTypeSecurityEvent     = "secevent+jwt"
	contentTypeSecurityEvent = "application/secevent+jwt"
)

type Configuration struct {
	SpecVersion            string                         `json:"spec_version,omitempty"`
	Issuer                 string                         `json:"issuer"`
	JWKSURI                string                         `json:"jwks_uri,omitempty"`
	DeliveryMethods        []goidc.SSFDeliveryMethod      `json:"delivery_methods_supported,omitempty"`
	ConfigurationEndpoint  string                         `json:"configuration_endpoint,omitempty"`
	StatusEndpoint         string                         `json:"status_endpoint,omitempty"`
	AddSubjectEndpoint     string                         `json:"add_subject_endpoint,omitempty"`
	RemoveSubjectEndpoint  string                         `json:"remove_subject_endpoint,omitempty"`
	VerificationEndpoint   string                         `json:"verification_endpoint,omitempty"`
	CriticalSubjectMembers []string                       `json:"critical_subject_members,omitempty"`
	AuthorizationSchemes   []goidc.SSFAuthorizationScheme `json:"authorization_schemes,omitempty"`
	DefaultSubjects        goidc.SSFDefaultSubject        `json:"default_subjects,omitempty"`
}

type request struct {
	ID              string               `json:"stream_id"`
	EventsRequested []goidc.SSFEventType `json:"events_requested"`
	Delivery        delivery             `json:"delivery"`
	Description     string               `json:"description,omitempty"`
}

type response struct {
	ID                      string               `json:"stream_id"`
	Issuer                  string               `json:"iss"`
	Audience                Audiences            `json:"aud"`
	EventsSupported         []goidc.SSFEventType `json:"events_supported"`
	EventsRequested         []goidc.SSFEventType `json:"events_requested"`
	EventsDelivered         []goidc.SSFEventType `json:"events_delivered"`
	Delivery                delivery             `json:"delivery"`
	MinVerificationInterval int                  `json:"min_verification_interval,omitempty"`
	Description             string               `json:"description,omitempty"`
	InactivityTimeout       int                  `json:"inactivity_timeout,omitempty"`
}

type delivery struct {
	Method              goidc.SSFDeliveryMethod `json:"method"`
	Endpoint            string                  `json:"endpoint_url,omitempty"`
	AuthorizationHeader string                  `json:"authorization_header,omitempty"`
}

type requestStatus struct {
	ID           string                     `json:"stream_id"`
	Status       goidc.SSFEventStreamStatus `json:"status"`
	StatusReason string                     `json:"status_reason,omitempty"`
}

type responseStatus struct {
	ID           string                     `json:"stream_id"`
	Status       goidc.SSFEventStreamStatus `json:"status"`
	StatusReason string                     `json:"status_reason,omitempty"`
}

type requestSubject struct {
	StreamID string           `json:"stream_id"`
	Subject  goidc.SSFSubject `json:"subject"`
	Verified *bool            `json:"verified,omitempty"`
}

type requestPollEvents struct {
	MaxEvents         *int `json:"maxEvents,omitempty"`
	ReturnImmediately bool `json:"returnImmediately,omitempty"`
	// Acknowledgements is a list of JWT IDs of the events that have been acknowledged.
	Acknowledgements []string `json:"acks,omitempty"`
	// Errors is a map of JWT IDs to errors of the events that have been delivered.
	Errors map[string]goidc.SSFEventError `json:"setErrs,omitempty"`
}

type responsePollEvents struct {
	SecurityEventTokens map[string]string `json:"sets"`
	MoreAvailable       bool              `json:"moreAvailable"`
}

type requestVerificationEvent struct {
	StreamID string `json:"stream_id"`
	State    string `json:"state,omitempty"`
}

type securityEventToken struct {
	Issuer      string                     `json:"iss"`
	JWTID       string                     `json:"jti"`
	Audience    Audiences                  `json:"aud"`
	IssuedAt    int                        `json:"iat"`
	Transaction string                     `json:"txn,omitempty"`
	Subject     goidc.SSFSubject           `json:"sub_id"`
	Events      map[goidc.SSFEventType]any `json:"events"`
}
