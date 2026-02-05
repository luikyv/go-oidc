package goidc

import (
	"context"
	"net/http"
)

// SSFEventStreamManager manages the lifecycle of SSF event streams.
type SSFEventStreamManager interface {
	Create(context.Context, *SSFEventStream) error
	Update(context.Context, *SSFEventStream) error
	EventStream(context.Context, string) (*SSFEventStream, error)
	EventStreams(ctx context.Context, receiverID string) ([]*SSFEventStream, error)
	Delete(context.Context, string) error
}

// SSFEventStreamSubjectManager manages subjects associated with event streams.
// Subjects define which entities (users, devices, sessions, etc.) an event stream applies to.
type SSFEventStreamSubjectManager interface {
	Add(ctx context.Context, streamID string, subject SSFSubject, opts SSFSubjectOptions) error
	Remove(ctx context.Context, streamID string, sub SSFSubject) error
}

// SSFEventPollManager manages event queuing and polling for poll-based delivery [RFC 8936].
// This interface is only used when the stream's delivery method is [SSFDeliveryMethodPoll].
type SSFEventPollManager interface {
	// Save saves an event to the stream's pending queue for later polling.
	Save(ctx context.Context, streamID string, event SSFEvent) error
	// Poll retrieves pending events without removing them from the queue.
	// Events remain pending until explicitly acknowledged via [SSFEventPollManager.Acknowledge].
	Poll(ctx context.Context, streamID string, opts SSFPollOptions) (SSFEvents, error)
	// Acknowledge marks events as successfully delivered and removes them from the queue.
	Acknowledge(ctx context.Context, streamID string, jtis []string, opts SSFAcknowledgementOptions) error
	// AcknowledgeErrors reports delivery errors for specific events.
	AcknowledgeErrors(ctx context.Context, streamID string, errs map[string]SSFEventError, opts SSFAcknowledgementOptions) error
}

// SSFEventStreamVerificationManager manages the lifecycle of verification events for event streams.
type SSFEventStreamVerificationManager interface {
	// Trigger triggers a verification event for the given stream.
	Trigger(ctx context.Context, streamID string, opts SSFStreamVerificationOptions) error
}

// SSFEventStream represents a configured event stream between a transmitter and receiver.
// See [SSF 1.0 §8.1.1] for the stream configuration schema.
type SSFEventStream struct {
	ID         string `json:"id"`
	ReceiverID string `json:"receiver_id"`
	// Audiences is a list of audiences for the event stream.
	// It defaults to a one-element slice containing the receiver ID.
	Audiences           []string             `json:"audiences"`
	Status              SSFEventStreamStatus `json:"status"`
	StatusReason        string               `json:"status_reason,omitempty"`
	EventsSupported     []SSFEventType       `json:"events_supported"`
	EventsRequested     []SSFEventType       `json:"events_requested"`
	EventsDelivered     []SSFEventType       `json:"events_delivered"`
	DeliveryMethod      SSFDeliveryMethod    `json:"delivery_method"`
	DeliveryEndpoint    string               `json:"delivery_endpoint,omitempty"`
	AuthorizationHeader string               `json:"authorization_header,omitempty"`
	Description         string               `json:"description,omitempty"`
	CreatedAtTimestamp  int                  `json:"created_at"`
	ExpiresAtTimestamp  int                  `json:"expires_at,omitempty"`
}

type SSFEventType string

const (
	SSFEventTypeVerification             SSFEventType = "https://schemas.openid.net/secevent/ssf/event-type/verification"
	SSFEventTypeStreamUpdated            SSFEventType = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"
	SSFEventTypeCAEPSessionRevoked       SSFEventType = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	SSFEventTypeCAEPTokenClaimsChange    SSFEventType = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
	SSFEventTypeCAEPCredentialChange     SSFEventType = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
	SSFEventTypeCAEPAssuranceLevelChange SSFEventType = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
)

type SSFDeliveryMethod string

const (
	SSFDeliveryMethodPush SSFDeliveryMethod = "urn:ietf:rfc:8935"
	SSFDeliveryMethodPoll SSFDeliveryMethod = "urn:ietf:rfc:8936"
)

type SSFSubject struct {
	Format SSFSubjectFormat `json:"format"`
	// ID is the ID of the subject.
	// It is used to identify the subject when the format is [SSFSubjectFormatOpaque].
	ID string `json:"id,omitempty"`
	// Email is the email of the subject.
	// It is used to identify the subject when the format is [SSFSubjectFormatEmail].
	Email string `json:"email,omitempty"`
	// PhoneNumber is the phone number of the subject.
	// It is used to identify the subject when the format is [SSFSubjectFormatPhoneNumber].
	Phone string `json:"phone_number,omitempty"`
	// URI is the URI of the subject.
	// It is used to identify the subject when the format is [SSFSubjectFormatAccount] or [SSFSubjectFormatURI].
	URI string `json:"uri,omitempty"`
	// Iss is the issuer of the subject.
	// It is used to identify the subject when the format is [SSFSubjectFormatIssuerSubject], [SSFSubjectFormatJWTID] or [SSFSubjectFormatSAMLAssertionID].
	Iss string `json:"iss,omitempty"`
	// Sub is the subject of the subject.
	// It is used to identify the subject when the format is [SSFSubjectFormatIssuerSubject].
	Sub string `json:"sub,omitempty"`
	// URL is the URL of the subject.
	// It is used to identify the subject when the format is [SSFSubjectDecentralizedIdentifier].
	URL string `json:"url,omitempty"`
	// JTI is the JWT ID of the token.
	// It is used to identify the token when the format is [SSFSubjectFormatJWTID].
	JTI string `json:"jti,omitempty"`
	// AssertionID is the assertion ID of the subject.
	// It is used to identify the subject when the format is [SSFSubjectFormatSAMLAssertionID].
	AssertionID string `json:"assertion_id,omitempty"`
	// Issuer is the issuer of the assertion.
	// It is used to identify the assertion when the format is [SSFSubjectFormatSAMLAssertionID].
	Issuer string `json:"issuer,omitempty"`
	// IPAddresses is a list of IP addresses of the subject.
	// It is used to identify the subject when the format is [SSFSubjectFormatIPAddresses].
	IPAddresses []string `json:"ip-addresses,omitempty"`
	// Identifiers is a list of aliases for the subject.
	// It is used to identify the subject when the format is [SSFSubjectFormatAliases].
	Identifiers          []SSFSubject          `json:"identifiers,omitempty"`
	User                 *SSFSubject           `json:"user,omitempty"`
	Tenant               *SSFSubject           `json:"tenant,omitempty"`
	Device               *SSFSubject           `json:"device,omitempty"`
	Session              *SSFSubject           `json:"session,omitempty"`
	OrganizationalUnit   *SSFSubject           `json:"org_unit,omitempty"`
	Application          *SSFSubject           `json:"application,omitempty"`
	Group                *SSFSubject           `json:"group,omitempty"`
	AdditionalProperties map[string]SSFSubject `json:"additional_properties,omitempty"`
}

type SSFSubjectFormat string

const (
	SSFSubjectFormatComplex           SSFSubjectFormat = "complex"
	SSFSubjectFormatOpaque            SSFSubjectFormat = "opaque"
	SSFSubjectFormatEmail             SSFSubjectFormat = "email"
	SSFSubjectFormatPhoneNumber       SSFSubjectFormat = "phone_number"
	SSFSubjectFormatAccount           SSFSubjectFormat = "account"
	SSFSubjectFormatIssuerSubject     SSFSubjectFormat = "iss_sub"
	SSFSubjectDecentralizedIdentifier SSFSubjectFormat = "did"
	SSFSubjectFormatURI               SSFSubjectFormat = "uri"
	SSFSubjectFormatAliases           SSFSubjectFormat = "aliases"
	SSFSubjectJWTID                   SSFSubjectFormat = "jwt_id"
	SSFSubjectSAMLAssertionID         SSFSubjectFormat = "saml_assertion_id"
	SSFSubjectIPAddresses             SSFSubjectFormat = "ip-addresses"
)

type SSFSubjectOptions struct {
	Verified bool
}

type SSFAuthorizationScheme struct {
	SpecVersion string `json:"spec_version"`
}

type SSFDefaultSubject string

const (
	SSFDefaultSubjectAll  SSFDefaultSubject = "ALL"
	SSFDefaultSubjectNone SSFDefaultSubject = "NONE"
)

// SSFAuthenticatedReceiverFunc is a function that receives an authenticated request and returns the receiver ID.
// It is used to identify the receiver of the event stream.
type SSFAuthenticatedReceiverFunc func(*http.Request) (SSFReceiver, error)

type SSFReceiver struct {
	ID string
	// Audiences is a list of audiences for the receiver of the event stream.
	// If empty, the receiver ID will be used as the audience.
	Audiences       []string
	EventsSupported []SSFEventType
}

type SSFEvents struct {
	Events        []SSFEvent
	MoreAvailable bool
}

type SSFPollOptions struct {
	// MaxEvents is the maximum number of events to return.
	// If nil, there's no limit on the number of events to return.
	MaxEvents         *int
	ReturnImmediately bool
}

type SSFAcknowledgementOptions struct {
	ReturnImmediately bool
}

type SSFEvent struct {
	JWTID   string
	Type    SSFEventType
	Subject SSFSubject
	// Transaction is the transaction ID of the event.
	Transaction string
	// Claims is the claims of the event.
	Claims any
}

type SSFEventError struct {
	Error       SSFEventErrorCode `json:"err"`
	Description string            `json:"description"`
}

type SSFEventErrorCode string

const (
	SSFEventErrorCodeAuthenticationFailed SSFEventErrorCode = "authentication_failed"
	SSFEventErrorCodeInvalidRequest       SSFEventErrorCode = "invalid_request"
	SSFEventErrorCodeInvalidKey           SSFEventErrorCode = "invalid_key"
	SSFEventErrorCodeInvalidIssuer        SSFEventErrorCode = "invalid_issuer"
	SSFEventErrorCodeInvalidAudience      SSFEventErrorCode = "invalid_audience"
	SSFEventErrorCodeAccessDenied         SSFEventErrorCode = "access_denied"
)

// SSFEventStreamStatus represents the current state of an event stream.
type SSFEventStreamStatus string

const (
	SSFEventStreamStatusEnabled  SSFEventStreamStatus = "enabled"
	SSFEventStreamStatusPaused   SSFEventStreamStatus = "paused"
	SSFEventStreamStatusDisabled SSFEventStreamStatus = "disabled"
)

type SSFStreamVerificationOptions struct {
	State string
}

func NewSSFVerificationEvent(streamID string, opts SSFStreamVerificationOptions) SSFEvent {
	claims := make(map[string]any)
	if opts.State != "" {
		claims["state"] = opts.State
	}
	return SSFEvent{
		Type: SSFEventTypeVerification,
		Subject: SSFSubject{
			Format: SSFSubjectFormatOpaque,
			ID:     streamID,
		},
		Claims: claims,
	}
}
