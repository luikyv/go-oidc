package goidc

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
)

const (
	SSFClaimEventTimestamp   string = "event_timestamp"
	SSFClaimInitiatingEntity string = "initiating_entity"
	SSFClaimReasonAdmin      string = "reason_admin"
	SSFClaimReasonUser       string = "reason_user"
	SSFClaimTokenClaims      string = "claims"
	SSFClaimCredentialType   string = "credential_type" //nolint:gosec
	SSFClaimChangeType       string = "change_type"
	SSFClaimFriendlyName     string = "friendly_name"
	SSFClaimX509Issuer       string = "x509_issuer"
	SSFClaimX509Serial       string = "x509_serial"
	SSFClaimFIDO2AAGUID      string = "fido2_aaguid"
	SSFClaimPreviousStatus   string = "previous_status"
	SSFClaimCurrentStatus    string = "current_status"
	SSFClaimPreviousLevel    string = "previous_level"
	SSFClaimCurrentLevel     string = "current_level"
	SSFClaimChangeDirection  string = "change_direction"
)

type SSFInitiatingEntity string

const (
	SSFInitiatingEntityAdmin  SSFInitiatingEntity = "admin"
	SSFInitiatingEntityUser   SSFInitiatingEntity = "user"
	SSFInitiatingEntityPolicy SSFInitiatingEntity = "policy"
	SSFInitiatingEntitySystem SSFInitiatingEntity = "system"
)

type SSFCredentialType string

const (
	SSFCredentialTypePassword             SSFCredentialType = "password"
	SSFCredentialTypePIN                  SSFCredentialType = "pin"
	SSFCredentialTypeX509                 SSFCredentialType = "x509"
	SSFCredentialTypeFIDO2Platform        SSFCredentialType = "fido2-platform"
	SSFCredentialTypeFIDO2Roaming         SSFCredentialType = "fido2-roaming"
	SSFCredentialTypeFIDOU2F              SSFCredentialType = "fido-u2f"
	SSFCredentialTypeVerifiableCredential SSFCredentialType = "verifiable-credential" //nolint:gosec
	SSFCredentialTypePhoneVoice           SSFCredentialType = "phone-voice"
	SSFCredentialTypePhoneSMS             SSFCredentialType = "phone-sms"
	SSFCredentialTypeApp                  SSFCredentialType = "app"
)

type SSFCredentialChangeType string

const (
	SSFCredentialChangeTypeCreate SSFCredentialChangeType = "create"
	SSFCredentialChangeTypeRevoke SSFCredentialChangeType = "revoke"
	SSFCredentialChangeTypeUpdate SSFCredentialChangeType = "update"
	SSFCredentialChangeTypeDelete SSFCredentialChangeType = "delete"
)

// SSFStreamManager manages the lifecycle of SSF event streams.
type SSFStreamManager interface {
	SaveStream(context.Context, *SSFStream) error
	// Stream returns the stream identified by id.
	// It must return [ErrNotFound] when the stream does not exist.
	Stream(context.Context, string) (*SSFStream, error)
	// Streams returns the streams associated with the receiver.
	Streams(ctx context.Context, receiverID string) ([]*SSFStream, error)
	DeleteStream(context.Context, string) error
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

// SSFPollingManager manages event queuing and polling for poll-based delivery [RFC 8936].
// This interface is only used when the stream's delivery method is [SSFDeliveryMethodPoll].
type SSFPollingManager interface {
	// PollEvents retrieves pending events without removing them from the queue.
	// Events remain pending until explicitly acknowledged via [SSFEventPollManager.AcknowledgeEvents].
	PollEvents(ctx context.Context, streamID string, opts SSFPollOptions) (SSFEvents, error)
	// AcknowledgeEvents marks events as successfully delivered and removes them from the queue.
	AcknowledgeEvents(ctx context.Context, streamID string, ids []string, opts SSFAcknowledgementOptions) error
	// AcknowledgeEventErrors reports delivery errors for specific events.
	AcknowledgeEventErrors(ctx context.Context, streamID string, errs []SSFEventError, opts SSFAcknowledgementOptions) error
}

// SSFVerificationManager schedules SSF verification events for event streams.
type SSFVerificationManager interface {
	// ScheduleVerificationEvent schedules the verification event for the stream
	// identified by streamID.
	ScheduleVerificationEvent(ctx context.Context, streamID string, event SSFEvent) error
}

// SSFStream represents a configured event stream between a transmitter and receiver.
// See [SSF 1.0 §8.1.1] for the stream configuration schema.
type SSFStream struct {
	ID         string `json:"id"`
	ReceiverID string `json:"receiver_id"`
	// Audiences is a list of audiences for the event stream.
	// It defaults to a one-element slice containing the receiver ID.
	Audiences    Audiences       `json:"audiences"`
	Status       SSFStreamStatus `json:"status"`
	StatusReason string          `json:"status_reason,omitempty"`
	// EventsSupported is the set of event types supported for this stream when
	// it was created or last updated.
	EventsSupported []SSFEventType `json:"events_supported"`
	// EventsRequested is the set of event types requested by the receiver for
	// this stream.
	EventsRequested []SSFEventType `json:"events_requested"`
	// EventsDelivered is the set of event types the transmitter will include in
	// this stream. It must be a subset of EventsSupported and EventsRequested.
	EventsDelivered []SSFEventType `json:"events_delivered"`
	Delivery        struct {
		Method              SSFDeliveryMethod `json:"method"`
		Endpoint            string            `json:"endpoint,omitempty"`
		AuthorizationHeader string            `json:"authorization_header,omitempty"`
	} `json:"delivery"`
	Description string `json:"description,omitempty"`
	CreatedAt   int    `json:"created_at"`
	// InactiveAt is the time at which the stream becomes inactive.
	// A value of 0 means no inactivity deadline is set.
	InactiveAt int            `json:"inactive_at,omitempty"`
	VerifiedAt int            `json:"verified_at,omitempty"`
	Store      map[string]any `json:"store,omitempty"`
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
	Identifiers        []SSFSubject          `json:"identifiers,omitempty"`
	User               *SSFSubject           `json:"user,omitempty"`
	Tenant             *SSFSubject           `json:"tenant,omitempty"`
	Device             *SSFSubject           `json:"device,omitempty"`
	Session            *SSFSubject           `json:"session,omitempty"`
	OrganizationalUnit *SSFSubject           `json:"org_unit,omitempty"`
	Application        *SSFSubject           `json:"application,omitempty"`
	Group              *SSFSubject           `json:"group,omitempty"`
	AdditionalMembers  map[string]SSFSubject `json:"-"`
}

func (s *SSFSubject) UnmarshalJSON(data []byte) error {
	type subject SSFSubject
	s.AdditionalMembers = nil
	if err := json.Unmarshal(data, (*subject)(s)); err != nil {
		return err
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	t := reflect.TypeFor[subject]()
	for i := range t.NumField() {
		tag := t.Field(i).Tag.Get("json")
		if name, _, _ := strings.Cut(tag, ","); name != "" && name != "-" {
			delete(raw, name)
		}
	}

	if len(raw) == 0 {
		return nil
	}

	s.AdditionalMembers = make(map[string]SSFSubject, len(raw))
	for name, value := range raw {
		var subject SSFSubject
		if err := json.Unmarshal(value, &subject); err != nil {
			return err
		}
		s.AdditionalMembers[name] = subject
	}
	return nil
}

func (s SSFSubject) MarshalJSON() ([]byte, error) {
	type subject SSFSubject
	attributesBytes, err := json.Marshal(subject(s))
	if err != nil {
		return nil, err
	}

	var rawValues map[string]any
	if err := json.Unmarshal(attributesBytes, &rawValues); err != nil {
		return nil, err
	}

	// Inline additional complex subject members.
	for name, member := range s.AdditionalMembers {
		rawValues[name] = member
	}

	return json.Marshal(rawValues)
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

// SSFAuthScheme describes an authorization scheme supported by the
// transmitter's SSF management APIs.
// See [SSF 1.0 §7.1].
type SSFAuthScheme struct {
	// SpecURN identifies the authorization scheme specification.
	SpecURN SSFAuthSchemeURN `json:"spec_urn"`
}

type SSFAuthSchemeURN string

const (
	// SSFAuthchemeURNRFC6749 indicates that the receiver may obtain an access
	// token using the Client Credentials Grant from RFC 6749 §4.4, or another
	// method suitable for the receiver and transmitter.
	SSFAuthchemeURNRFC6749 SSFAuthSchemeURN = "urn:ietf:rfc:6749"
	// SSFAuthchemeURNRFC8705 indicates that the receiver may authenticate or
	// use certificate-bound access tokens with OAuth 2.0 Mutual-TLS as defined
	// by RFC 8705.
	SSFAuthchemeURNRFC8705 SSFAuthSchemeURN = "urn:ietf:rfc:8705"
)

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

// SSFReceiverFunc is a function that receives an authenticated request and returns the receiver ID.
// It is used to identify the receiver of the event stream.
type SSFReceiverFunc func(context.Context) (SSFReceiver, error)

type SSFReceiver struct {
	ID string
	// Audiences is a list of audiences for the receiver of the event stream.
	// If empty, the receiver ID will be used as the audience.
	Audiences []string
	// EventTypes is the list of event types supported for this receiver.
	// If nil, the provider's global event types are used. Event types not in
	// the provider's global configuration are ignored.
	// If an empty slice, the receiver has not event type allowed.
	EventTypes []SSFEventType
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
	// Transaction identifies the underlying cause that produced the SET and
	// it may be reused across different SETs generated for the same cause.
	// See [SSF 1.0 §4.1.9].
	Transaction string `json:"txn,omitempty"`
	// Claims is the claims of the event.
	Claims map[string]any `json:"claims,omitempty"`
	// IssuedAt is the time at which the Security Event Token is issued.
	// It is used as the SET "iat" claim.
	IssuedAt int `json:"created_at"`
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
	SSFEventErrorCodeInvalidState         SSFEventErrorCode = "invalid_state"
)

// SSFStreamStatus represents the current state of an event stream.
// See [SSF 1.0 §8.1.2].
type SSFStreamStatus string

const (
	// SSFStreamStatusEnabled means the transmitter must transmit events
	// according to the stream's configured delivery method.
	SSFStreamStatusEnabled SSFStreamStatus = "enabled"
	// SSFStreamStatusPaused means the transmitter must not transmit events
	// while paused, but may hold events for later transmission when the stream
	// becomes enabled again.
	SSFStreamStatusPaused SSFStreamStatus = "paused"
	// SSFStreamStatusDisabled means the transmitter must not transmit
	// events and will not hold them for later transmission.
	SSFStreamStatusDisabled SSFStreamStatus = "disabled"
)

// SSFStatusHandleFunc is called before applying a receiver-requested stream
// status change. The handler receives the current stream and the requested
// status options, and may reject the change by returning an error.
type SSFStatusHandleFunc func(context.Context, *SSFStream, SSFStatusOptions) error

// SSFStatusOptions carries a receiver-requested stream status update.
type SSFStatusOptions struct {
	// Status is the requested stream status.
	Status SSFStreamStatus
	// Reason is the optional reason for the requested status change.
	Reason string
}
