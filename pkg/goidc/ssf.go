package goidc

import (
	"context"

	"github.com/luikyv/go-oidc/internal/timeutil"
)

// SSFEventStreamManager manages the lifecycle of SSF event streams.
type SSFEventStreamManager interface {
	CreateEventStream(context.Context, *SSFEventStream) error
	UpdateEventStream(context.Context, *SSFEventStream) error
	// EventStream returns the event stream identified by id.
	// It must return [ErrNotFound] when the stream does not exist.
	EventStream(context.Context, string) (*SSFEventStream, error)
	// EventStreams returns the event streams associated with the receiver.
	EventStreams(ctx context.Context, receiverID string) ([]*SSFEventStream, error)
	DeleteEventStream(context.Context, string) error
}

// SSFSubjectManager manages the subjects associated with an event stream.
// It is used by the SSF subject management API.
// See [SSF 1.0 §8.1.3].
type SSFSubjectManager interface {
	// AddStreamSubject adds a subject to the event stream identified by streamID.
	AddStreamSubject(ctx context.Context, streamID string, subject SSFSubject, opts SSFSubjectOptions) error
	// RemoveStreamSubject removes a subject from the event stream identified by streamID.
	RemoveStreamSubject(ctx context.Context, streamID string, sub SSFSubject) error
}

// SSFEventPollManager manages event queuing and polling for poll-based delivery [RFC 8936].
// This interface is only used when the stream's delivery method is [SSFDeliveryMethodPoll].
type SSFEventPollManager interface {
	// PollEvents retrieves pending events without removing them from the queue.
	// Events remain pending until explicitly acknowledged via [SSFEventPollManager.AcknowledgeEvents].
	PollEvents(ctx context.Context, streamID string, opts SSFPollOptions) (SSFEvents, error)
	// AcknowledgeEvents marks events as successfully delivered and removes them from the queue.
	AcknowledgeEvents(ctx context.Context, streamID string, ids []string, opts SSFAcknowledgementOptions) error
	// AcknowledgeEventErrors reports delivery errors for specific events.
	AcknowledgeEventErrors(ctx context.Context, streamID string, errs []SSFEventError, opts SSFAcknowledgementOptions) error
}

type SSFVerificationManager interface {
	ScheduleVerificationEvent(ctx context.Context, streamID string, opts SSFStreamVerificationOptions) error
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
	CreatedAt           int                  `json:"created_at"`
	ExpiresAt           int                  `json:"expires_at,omitempty"`
	VerifiedAt          int                  `json:"verified_at,omitempty"`
}

type SSFEventType string

const (
	// SSFEventTypeVerification [OpenID Shared Signals Framework Specification 1.0 §8.1.4.1].
	SSFEventTypeVerification SSFEventType = "https://schemas.openid.net/secevent/ssf/event-type/verification"
	// SSFEventTypeStreamUpdated [OpenID Shared Signals Framework Specification 1.0 §8.1.5].
	SSFEventTypeStreamUpdated SSFEventType = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"
	// SSFEventTypeCAEPSessionRevoked [OpenID Continuous Access Evaluation Profile 1.0 §3.1].
	SSFEventTypeCAEPSessionRevoked SSFEventType = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	// SSFEventTypeCAEPTokenClaimsChange [OpenID Continuous Access Evaluation Profile 1.0 §3.2].
	SSFEventTypeCAEPTokenClaimsChange SSFEventType = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change" //nolint:gosec
	// SSFEventTypeCAEPCredentialChange [OpenID Continuous Access Evaluation Profile 1.0 §3.3].
	SSFEventTypeCAEPCredentialChange SSFEventType = "https://schemas.openid.net/secevent/caep/event-type/credential-change" //nolint:gosec
	// SSFEventTypeCAEPAssuranceLevelChange [OpenID Continuous Access Evaluation Profile 1.0 §3.4].
	SSFEventTypeCAEPAssuranceLevelChange SSFEventType = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change" //nolint:gosec
	// SSFEventTypeCAEPDeviceComplianceChange [OpenID Continuous Access Evaluation Profile 1.0 §3.5].
	SSFEventTypeCAEPDeviceComplianceChange SSFEventType = "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"
	// SSFEventTypeCAEPSessionEstablished [OpenID Continuous Access Evaluation Profile 1.0 §3.6].
	SSFEventTypeCAEPSessionEstablished SSFEventType = "https://schemas.openid.net/secevent/caep/event-type/session-established"
	// SSFEventTypeCAEPSessionPresented [OpenID Continuous Access Evaluation Profile 1.0 §3.7].
	SSFEventTypeCAEPSessionPresented SSFEventType = "https://schemas.openid.net/secevent/caep/event-type/session-presented"
	// SSFEventTypeCAEPRiskLevelChange [OpenID Continuous Access Evaluation Profile 1.0 §3.8].
	SSFEventTypeCAEPRiskLevelChange SSFEventType = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change"
	// SSFEventTypeRISCAccountCredentialChangeRequired [OpenID RISC Profile Specification 1.0 §2.1].
	SSFEventTypeRISCAccountCredentialChangeRequired SSFEventType = "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required" //nolint:gosec
	// SSFEventTypeRISCAccountPurged [OpenID RISC Profile Specification 1.0 §2.2].
	SSFEventTypeRISCAccountPurged SSFEventType = "https://schemas.openid.net/secevent/risc/event-type/account-purged"
	// SSFEventTypeRISCAccountDisabled [OpenID RISC Profile Specification 1.0 §2.3].
	SSFEventTypeRISCAccountDisabled SSFEventType = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
	// SSFEventTypeRISCAccountEnabled [OpenID RISC Profile Specification 1.0 §2.4].
	SSFEventTypeRISCAccountEnabled SSFEventType = "https://schemas.openid.net/secevent/risc/event-type/account-enabled"
	// SSFEventTypeRISCIdentifierChanged [OpenID RISC Profile Specification 1.0 §2.5].
	SSFEventTypeRISCIdentifierChanged SSFEventType = "https://schemas.openid.net/secevent/risc/event-type/identifier-changed"
	// SSFEventTypeRISCIdentifierRecycled [OpenID RISC Profile Specification 1.0 §2.6].
	SSFEventTypeRISCIdentifierRecycled SSFEventType = "https://schemas.openid.net/secevent/risc/event-type/identifier-recycled"
	// SSFEventTypeRISCIdentifierCompromised [OpenID RISC Profile Specification 1.0 §2.7].
	SSFEventTypeRISCIdentifierCompromised SSFEventType = "https://schemas.openid.net/secevent/risc/event-type/credential-compromise"
	// SSFEventTypeRISCIdentifierOptIn [OpenID RISC Profile Specification 1.0 §2.8.1].
	SSFEventTypeRISCIdentifierOptIn SSFEventType = "https://schemas.openid.net/secevent/risc/event-type/opt-in"
	// SSFEventTypeRISCIdentifierOptOutInitiated [OpenID RISC Profile Specification 1.0 §2.8.2].
	SSFEventTypeRISCIdentifierOptOutInitiated SSFEventType = "https://schemas.openid.net/secevent/risc/event-type/opt-out-initiated"
	// SSFEventTypeRISCIdentifierOptOutCancelled [OpenID RISC Profile Specification 1.0 §2.8.3].
	SSFEventTypeRISCIdentifierOptOutCancelled SSFEventType = "https://schemas.openid.net/secevent/risc/event-type/opt-out-cancelled"
	// SSFEventTypeRISCIdentifierOptOutEffective [OpenID RISC Profile Specification 1.0 §2.8.4].
	SSFEventTypeRISCIdentifierOptOutEffective SSFEventType = "https://schemas.openid.net/secevent/risc/event-type/opt-out-effective"
	// SSFEventTypeRISCRecoveryActivated [OpenID RISC Profile Specification 1.0 §2.9].
	SSFEventTypeRISCRecoveryActivated SSFEventType = "https://schemas.openid.net/secevent/risc/event-type/recovery-activated"
	// SSFEventTypeRISCRecoveryInformationChanged [OpenID RISC Profile Specification 1.0 §2.10].
	SSFEventTypeRISCRecoveryInformationChanged SSFEventType = "https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed"
	// SSFEventTypeRSSessionsRevoked [OpenID RISC Profile Specification 1.0 §2.11].
	SSFEventTypeRSSessionsRevoked SSFEventType = "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked"
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

// SSFSubjectOptions carries options for adding a subject to an event stream.
// See [SSF 1.0 §8.1.3].
type SSFSubjectOptions struct {
	// Verified indicates whether the receiver has verified the subject before
	// adding it to the stream. It defaults to true when omitted by the request.
	Verified bool
}

// SSFAuthorizationScheme describes an authorization scheme supported by the
// transmitter's SSF management APIs.
// See [SSF 1.0 §7.1].
type SSFAuthorizationScheme struct {
	// SpecificationURN identifies the authorization scheme specification.
	SpecificationURN string `json:"spec_urn"`
}

// SSFDefaultSubject defines whether newly created streams include subjects by
// default or require explicit subject registration.
// See [SSF 1.0 §7.1].
type SSFDefaultSubject string

const (
	// SSFDefaultSubjectAll means events for all subjects are delivered by default.
	SSFDefaultSubjectAll SSFDefaultSubject = "ALL"
	// SSFDefaultSubjectNone means subjects must be explicitly added before
	// events are delivered for them.
	SSFDefaultSubjectNone SSFDefaultSubject = "NONE"
)

// SSFAuthenticatedReceiverFunc is a function that receives an authenticated request and returns the receiver ID.
// It is used to identify the receiver of the event stream.
type SSFAuthenticatedReceiverFunc func(context.Context) (SSFReceiver, error)

type SSFReceiver struct {
	ID string
	// Audiences is a list of audiences for the receiver of the event stream.
	// If empty, the receiver ID will be used as the audience.
	Audiences []string
}

// SSFEvents is the result of polling pending SETs for an event stream.
// See [RFC 8936 §2.3].
type SSFEvents struct {
	// Events is the list of pending events returned by the poll operation.
	Events []SSFEvent
	// MoreAvailable indicates whether more unacknowledged SETs are available
	// after this response.
	MoreAvailable bool
}

// SSFPollOptions carries options for retrieving pending SETs through
// poll-based delivery.
// See [RFC 8936 §2.2, §2.4.1].
type SSFPollOptions struct {
	// MaxEvents is the maximum number of events to return.
	// If nil, there's no limit on the number of events to return.
	MaxEvents *int
	// ReturnImmediately indicates whether the transmitter should return
	// immediately when no SETs are available, instead of waiting as a long poll.
	ReturnImmediately bool
}

// SSFAcknowledgementOptions carries options for processing event
// acknowledgements or acknowledgement errors.
// See [RFC 8936 §2.2, §2.4.2-2.4.4].
type SSFAcknowledgementOptions struct {
	// ReturnImmediately indicates whether the transmitter should return
	// immediately after processing the acknowledgement when no SETs are
	// available, instead of waiting as a long poll.
	ReturnImmediately bool
}

// SSFEvent is an instance of a security event that will be delivered to, or
// polled by, the receiver as a Security Event Token (SET).
type SSFEvent struct {
	// ID is the event identifier. It is used as the SET "jti" claim.
	ID string `json:"id"`
	// Type is the event type URI.
	Type SSFEventType `json:"type"`
	// Subject identifies the subject of the event.
	Subject SSFSubject `json:"sub_id"`
	// Transaction is the transaction ID of the event.
	Transaction string `json:"txn,omitempty"`
	// Claims is the claims of the event.
	Claims any `json:"claims,omitempty"`
	// CreatedAt is the event creation time as a Unix timestamp.
	CreatedAt int `json:"created_at"`
}

// SSFEventError describes a receiver-reported error for a polled SET.
// See [RFC 8936 §2.4.3].
type SSFEventError struct {
	// ID is the SET "jti" claim identifying the event with an error.
	ID string `json:"-"`
	// Error is the machine-readable error code.
	Error SSFEventErrorCode `json:"err"`
	// Description is a human-readable explanation of the error.
	Description string `json:"description"`
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

func NewSSFVerificationEvent(id, streamID string, opts SSFStreamVerificationOptions) SSFEvent {
	claims := make(map[string]any)
	if opts.State != "" {
		claims["state"] = opts.State
	}
	return SSFEvent{
		ID:   id,
		Type: SSFEventTypeVerification,
		Subject: SSFSubject{
			Format: SSFSubjectFormatOpaque,
			ID:     streamID,
		},
		Claims:    claims,
		CreatedAt: timeutil.TimestampNow(),
	}
}

type SSFHandleExpiredEventStreamFunc func(context.Context, *SSFEventStream) error
