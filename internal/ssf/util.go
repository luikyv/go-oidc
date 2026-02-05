package ssf

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func PublishEvent(ctx oidc.Context, streamID string, event goidc.SSFEvent) error {
	stream, err := ctx.SSFEventStream(streamID)
	if err != nil {
		return err
	}

	// Return an error if the stream did not subscribe to the event type and the event is not a verification event.
	if !slices.Contains(stream.EventsDelivered, event.Type) && !(ctx.SSFIsVerificationEnabled && event.Type == goidc.SSFEventTypeVerification) {
		return fmt.Errorf("stream did not subscribe to event type %s", event.Type)
	}

	if stream.Status != goidc.SSFEventStreamStatusEnabled {
		return nil
	}

	// Ensure the event has a JWTID.
	if event.JWTID == "" {
		event.JWTID = ctx.SSFJWTID()
	}

	switch stream.DeliveryMethod {
	case goidc.SSFDeliveryMethodPush:
		return pushEvent(ctx, stream, event)
	case goidc.SSFDeliveryMethodPoll:
		return ctx.SSFSaveEvent(streamID, event)
	default:
		return errors.New("unsupported delivery method")
	}
}

func pushEvent(ctx oidc.Context, stream *goidc.SSFEventStream, event goidc.SSFEvent) error {
	set, err := signEvent(ctx, stream, event)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx.Context(), http.MethodPost, stream.DeliveryEndpoint, strings.NewReader(set))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentTypeSecurityEvent)
	if stream.AuthorizationHeader != "" {
		req.Header.Set("Authorization", stream.AuthorizationHeader)
	}

	resp, err := ctx.SSFHTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("push failed with status %d", resp.StatusCode)
	}
	return nil
}

func newConfiguration(ctx oidc.Context) Configuration {
	config := Configuration{
		SpecVersion:            specVersion,
		Issuer:                 ctx.Issuer(),
		JWKSURI:                ctx.BaseURL() + ctx.SSFJWKSEndpoint,
		DeliveryMethods:        ctx.SSFDeliveryMethods,
		CriticalSubjectMembers: ctx.SSFCriticalSubjectMembers,
		AuthorizationSchemes:   ctx.SSFAuthorizationSchemes,
		DefaultSubjects:        ctx.SSFDefaultSubjects,
		ConfigurationEndpoint:  ctx.BaseURL() + ctx.SSFConfigurationEndpoint,
	}
	if ctx.SSFIsStatusManagementEnabled {
		config.StatusEndpoint = ctx.BaseURL() + ctx.SSFStatusEndpoint
	}
	if ctx.SSFIsSubjectManagementEnabled {
		config.AddSubjectEndpoint = ctx.BaseURL() + ctx.SSFAddSubjectEndpoint
		config.RemoveSubjectEndpoint = ctx.BaseURL() + ctx.SSFRemoveSubjectEndpoint
	}
	if ctx.SSFIsVerificationEnabled {
		config.VerificationEndpoint = ctx.BaseURL() + ctx.SSFVerificationEndpoint
	}
	return config
}

func createStream(ctx oidc.Context, req request) (response, error) {
	receiver, err := ctx.SSFAuthenticatedReceiver()
	if err != nil {
		return response{}, err
	}

	// [SSF 1.0 §8.1.1.1] Default to poll delivery when unspecified.
	if req.Delivery.Method == "" {
		req.Delivery.Method = goidc.SSFDeliveryMethodPoll
	}

	audiences := receiver.Audiences
	if len(audiences) == 0 {
		audiences = []string{receiver.ID}
	}
	eventsSupported := eventsSupported(ctx, receiver)
	stream := &goidc.SSFEventStream{
		ID:                  ctx.SSFEventStreamID(),
		ReceiverID:          receiver.ID,
		Audiences:           audiences,
		Status:              goidc.SSFEventStreamStatusEnabled,
		EventsSupported:     eventsSupported,
		EventsRequested:     req.EventsRequested,
		EventsDelivered:     intersection(eventsSupported, req.EventsRequested),
		DeliveryMethod:      req.Delivery.Method,
		DeliveryEndpoint:    req.Delivery.Endpoint,
		AuthorizationHeader: req.Delivery.AuthorizationHeader,
		Description:         req.Description,
		CreatedAtTimestamp:  timeutil.TimestampNow(),
	}
	if err := validateStream(ctx, stream); err != nil {
		return response{}, err
	}

	if err := ctx.SSFCreateEventStream(stream); err != nil {
		return response{}, err
	}

	return toResponse(ctx, stream), nil
}

func updateStream(ctx oidc.Context, req request) (response, error) {
	receiver, err := ctx.SSFAuthenticatedReceiver()
	if err != nil {
		return response{}, err
	}

	if req.ID == "" {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "stream_id is required")
	}

	// [SSF 1.0 §8.1.1.1] Default to poll delivery when unspecified.
	if req.Delivery.Method == "" {
		req.Delivery.Method = goidc.SSFDeliveryMethodPoll
	}

	stream, err := ctx.SSFEventStream(req.ID)
	if err != nil {
		return response{}, err
	}

	if stream.ReceiverID != receiver.ID {
		return response{}, goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied", errors.New("stream not owned by receiver"))
	}

	stream.EventsRequested = req.EventsRequested
	stream.EventsDelivered = intersection(eventsSupported(ctx, receiver), req.EventsRequested)
	stream.DeliveryMethod = req.Delivery.Method
	stream.DeliveryEndpoint = req.Delivery.Endpoint
	stream.AuthorizationHeader = req.Delivery.AuthorizationHeader
	stream.Description = req.Description
	if err := validateStream(ctx, stream); err != nil {
		return response{}, err
	}

	if err := ctx.SSFUpdateEventStream(stream); err != nil {
		return response{}, err
	}

	return toResponse(ctx, stream), nil

}

func patchStream(ctx oidc.Context, req request) (response, error) {
	receiver, err := ctx.SSFAuthenticatedReceiver()
	if err != nil {
		return response{}, err
	}

	if req.ID == "" {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "stream_id is required")
	}

	stream, err := ctx.SSFEventStream(req.ID)
	if err != nil {
		return response{}, err
	}

	if stream.ReceiverID != receiver.ID {
		return response{}, goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied", errors.New("stream not owned by receiver"))
	}

	if req.EventsRequested != nil {
		stream.EventsRequested = req.EventsRequested
		stream.EventsDelivered = intersection(eventsSupported(ctx, receiver), req.EventsRequested)
	}

	if req.Delivery.Method != "" {
		stream.DeliveryMethod = req.Delivery.Method
	}

	if req.Delivery.Endpoint != "" {
		stream.DeliveryEndpoint = req.Delivery.Endpoint
	}

	if req.Delivery.AuthorizationHeader != "" {
		stream.AuthorizationHeader = req.Delivery.AuthorizationHeader
	}

	if req.Description != "" {
		stream.Description = req.Description
	}

	if err := validateStream(ctx, stream); err != nil {
		return response{}, err
	}

	if err := ctx.SSFUpdateEventStream(stream); err != nil {
		return response{}, err
	}

	return toResponse(ctx, stream), nil
}

func fetchStream(ctx oidc.Context, id string) (response, error) {
	receiver, err := ctx.SSFAuthenticatedReceiver()
	if err != nil {
		return response{}, err
	}

	stream, err := ctx.SSFEventStream(id)
	if err != nil {
		return response{}, err
	}

	if stream.ReceiverID != receiver.ID {
		return response{}, goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied", errors.New("stream not owned by receiver"))
	}

	return toResponse(ctx, stream), nil
}

func fetchStreams(ctx oidc.Context) ([]response, error) {
	receiver, err := ctx.SSFAuthenticatedReceiver()
	if err != nil {
		return []response{}, err
	}

	streams, err := ctx.SSFEventStreams(receiver.ID)
	if err != nil {
		return []response{}, err
	}

	responses := make([]response, 0, len(streams))
	for _, stream := range streams {
		responses = append(responses, toResponse(ctx, stream))
	}
	return responses, nil
}

func deleteStream(ctx oidc.Context, id string) error {
	receiver, err := ctx.SSFAuthenticatedReceiver()
	if err != nil {
		return err
	}

	stream, err := ctx.SSFEventStream(id)
	if err != nil {
		return err
	}

	if stream.ReceiverID != receiver.ID {
		return goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied", errors.New("stream not owned by receiver"))
	}

	return ctx.SSFDeleteEventStream(id)
}

func fetchStreamStatus(ctx oidc.Context, id string) (responseStatus, error) {
	receiver, err := ctx.SSFAuthenticatedReceiver()
	if err != nil {
		return responseStatus{}, err
	}

	stream, err := ctx.SSFEventStream(id)
	if err != nil {
		return responseStatus{}, err
	}

	if stream.ReceiverID != receiver.ID {
		return responseStatus{}, goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied", errors.New("stream not owned by receiver"))
	}

	if !ctx.SSFIsEventStreamStatusReadAllowed(receiver) {
		return responseStatus{}, goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied", errors.New("receiver not allowed to fetch event stream status"))
	}

	return responseStatus{
		ID:           stream.ID,
		Status:       stream.Status,
		StatusReason: stream.StatusReason,
	}, nil
}

func updateStreamStatus(ctx oidc.Context, req requestStatus) (responseStatus, error) {
	receiver, err := ctx.SSFAuthenticatedReceiver()
	if err != nil {
		return responseStatus{}, err
	}

	if !ctx.SSFIsEventStreamStatusWriteAllowed(receiver) {
		return responseStatus{}, goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied", errors.New("receiver not allowed to update event stream status"))
	}

	if req.ID == "" {
		return responseStatus{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "stream_id is required")
	}

	stream, err := ctx.SSFEventStream(req.ID)
	if err != nil {
		return responseStatus{}, err
	}

	if stream.ReceiverID != receiver.ID {
		return responseStatus{}, goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied", errors.New("stream not owned by receiver"))
	}

	stream.Status = req.Status
	stream.StatusReason = req.StatusReason
	if err := ctx.SSFUpdateEventStream(stream); err != nil {
		return responseStatus{}, err
	}

	return responseStatus{
		ID:           stream.ID,
		Status:       stream.Status,
		StatusReason: stream.StatusReason,
	}, nil
}

func addSubject(ctx oidc.Context, req requestSubject) error {
	_, _, err := receiverAndEventStream(ctx, req.StreamID)
	if err != nil {
		return err
	}

	if err := validateSubject(ctx, req.Subject); err != nil {
		return err
	}

	verified := true
	if req.Verified != nil {
		verified = *req.Verified
	}
	return ctx.SSFAddSubject(req.StreamID, req.Subject, goidc.SSFSubjectOptions{
		Verified: verified,
	})
}

func removeSubject(ctx oidc.Context, req requestSubject) error {
	_, _, err := receiverAndEventStream(ctx, req.StreamID)
	if err != nil {
		return err
	}

	if err := validateSubject(ctx, req.Subject); err != nil {
		return err
	}

	return ctx.SSFRemoveSubject(req.StreamID, req.Subject)
}

func validateStream(ctx oidc.Context, stream *goidc.SSFEventStream) error {
	if !slices.Contains(ctx.SSFDeliveryMethods, stream.DeliveryMethod) {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid delivery method")
	}

	if stream.DeliveryMethod == goidc.SSFDeliveryMethodPush {
		if stream.DeliveryEndpoint == "" {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "receiver delivery endpoint_url is required for push delivery method")
		}

		if _, err := url.Parse(stream.DeliveryEndpoint); err != nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid delivery endpoint_url", err)
		}
	}

	if stream.DeliveryMethod == goidc.SSFDeliveryMethodPoll {
		if stream.DeliveryEndpoint != "" {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "receiver delivery endpoint_url is not allowed for poll delivery method")
		}

		if stream.AuthorizationHeader != "" {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "authorization_header is not allowed for poll delivery method")
		}
	}

	return nil
}

// subjectAllowedFields maps each subject format to its allowed fields.
var subjectAllowedFields = map[goidc.SSFSubjectFormat]struct {
	id, email, phone, uri, iss, sub, url, jti, assertionID, issuer bool
	ipAddresses, identifiers                                       bool
	user, tenant, device, session, orgUnit, application, group     bool
	additionalProperties                                           bool
}{
	goidc.SSFSubjectFormatOpaque:            {id: true},
	goidc.SSFSubjectFormatEmail:             {email: true},
	goidc.SSFSubjectFormatPhoneNumber:       {phone: true},
	goidc.SSFSubjectFormatAccount:           {uri: true},
	goidc.SSFSubjectFormatURI:               {uri: true},
	goidc.SSFSubjectFormatIssuerSubject:     {iss: true, sub: true},
	goidc.SSFSubjectDecentralizedIdentifier: {url: true},
	goidc.SSFSubjectJWTID:                   {jti: true, iss: true},
	goidc.SSFSubjectSAMLAssertionID:         {assertionID: true, issuer: true},
	goidc.SSFSubjectIPAddresses:             {ipAddresses: true},
	goidc.SSFSubjectFormatAliases:           {identifiers: true},
	goidc.SSFSubjectFormatComplex:           {user: true, tenant: true, device: true, session: true, orgUnit: true, application: true, group: true, additionalProperties: true},
}

func validateSubject(ctx oidc.Context, sub goidc.SSFSubject) error {
	allowed, ok := subjectAllowedFields[sub.Format]
	if !ok {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "invalid subject format")
	}

	// Check disallowed fields are empty.
	if !allowed.id && sub.ID != "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "id is not allowed for "+string(sub.Format)+" subject format")
	}
	if !allowed.email && sub.Email != "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "email is not allowed for "+string(sub.Format)+" subject format")
	}
	if !allowed.phone && sub.Phone != "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "phone_number is not allowed for "+string(sub.Format)+" subject format")
	}
	if !allowed.uri && sub.URI != "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "uri is not allowed for "+string(sub.Format)+" subject format")
	}
	if !allowed.iss && sub.Iss != "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "iss is not allowed for "+string(sub.Format)+" subject format")
	}
	if !allowed.sub && sub.Sub != "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "sub is not allowed for "+string(sub.Format)+" subject format")
	}
	if !allowed.url && sub.URL != "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "url is not allowed for "+string(sub.Format)+" subject format")
	}
	if !allowed.jti && sub.JTI != "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "jti is not allowed for "+string(sub.Format)+" subject format")
	}
	if !allowed.assertionID && sub.AssertionID != "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "assertion_id is not allowed for "+string(sub.Format)+" subject format")
	}
	if !allowed.issuer && sub.Issuer != "" {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "issuer is not allowed for "+string(sub.Format)+" subject format")
	}
	if !allowed.ipAddresses && sub.IPAddresses != nil {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "ip-addresses is not allowed for "+string(sub.Format)+" subject format")
	}
	if !allowed.identifiers && sub.Identifiers != nil {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "identifiers is not allowed for "+string(sub.Format)+" subject format")
	}
	if !allowed.user && sub.User != nil {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "user is not allowed for "+string(sub.Format)+" subject format")
	}
	if !allowed.tenant && sub.Tenant != nil {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "tenant is not allowed for "+string(sub.Format)+" subject format")
	}
	if !allowed.device && sub.Device != nil {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "device is not allowed for "+string(sub.Format)+" subject format")
	}
	if !allowed.session && sub.Session != nil {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "session is not allowed for "+string(sub.Format)+" subject format")
	}
	if !allowed.orgUnit && sub.OrganizationalUnit != nil {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "org_unit is not allowed for "+string(sub.Format)+" subject format")
	}
	if !allowed.application && sub.Application != nil {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "application is not allowed for "+string(sub.Format)+" subject format")
	}
	if !allowed.group && sub.Group != nil {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "group is not allowed for "+string(sub.Format)+" subject format")
	}
	if !allowed.additionalProperties && sub.AdditionalProperties != nil {
		return goidc.NewError(goidc.ErrorCodeInvalidRequest, "additional properties are not allowed for "+string(sub.Format)+" subject format")
	}

	// Format-specific required field validation.
	switch sub.Format {
	case goidc.SSFSubjectFormatOpaque:
		if sub.ID == "" {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "id is required for opaque subject format")
		}
	case goidc.SSFSubjectFormatEmail:
		if sub.Email == "" {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "email is required for email subject format")
		}
	case goidc.SSFSubjectFormatPhoneNumber:
		if sub.Phone == "" {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "phone_number is required for phone_number subject format")
		}
	case goidc.SSFSubjectFormatAccount, goidc.SSFSubjectFormatURI:
		if sub.URI == "" {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "uri is required for "+string(sub.Format)+" subject format")
		}
	case goidc.SSFSubjectFormatIssuerSubject:
		if sub.Iss == "" {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "iss is required for iss_sub subject format")
		}
		if sub.Sub == "" {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "sub is required for iss_sub subject format")
		}
	case goidc.SSFSubjectDecentralizedIdentifier:
		if sub.URL == "" {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "url is required for did subject format")
		}
	case goidc.SSFSubjectJWTID:
		if sub.JTI == "" {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "jti is required for jwt_id subject format")
		}
		if sub.Iss == "" {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "iss is required for jwt_id subject format")
		}
	case goidc.SSFSubjectSAMLAssertionID:
		if sub.AssertionID == "" {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "assertion_id is required for saml_assertion_id subject format")
		}
		if sub.Issuer == "" {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "issuer is required for saml_assertion_id subject format")
		}
	case goidc.SSFSubjectIPAddresses:
		if len(sub.IPAddresses) == 0 {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "ip-addresses is required for ip-addresses subject format")
		}
	case goidc.SSFSubjectFormatAliases:
		if len(sub.Identifiers) == 0 {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "identifiers is required for aliases subject format")
		}
		for _, member := range sub.Identifiers {
			// [RFC 9493 §3.2.8] A member of an alias must not be an alias.
			if member.Format == goidc.SSFSubjectFormatAliases {
				return goidc.NewError(goidc.ErrorCodeInvalidRequest, "aliases cannot contain aliases")
			}
			if err := validateSubject(ctx, member); err != nil {
				return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid alias identifier", err)
			}
		}
	case goidc.SSFSubjectFormatComplex:
		// [SSF 1.0 §3.3] A complex subject must contain at least one field.
		if sub.User == nil && sub.Tenant == nil && sub.Device == nil && sub.Session == nil &&
			sub.OrganizationalUnit == nil && sub.Application == nil && sub.Group == nil {
			return goidc.NewError(goidc.ErrorCodeInvalidRequest, "at least one member is required for complex subject format")
		}
		// Recursively validate nested subjects.
		for _, nested := range []*goidc.SSFSubject{sub.User, sub.Tenant, sub.Device, sub.Session, sub.OrganizationalUnit, sub.Application, sub.Group} {
			if nested != nil {
				if err := validateSubject(ctx, *nested); err != nil {
					return err
				}
			}
		}
		for _, nested := range sub.AdditionalProperties {
			if err := validateSubject(ctx, nested); err != nil {
				return err
			}
		}
	}

	return nil
}

func toResponse(ctx oidc.Context, stream *goidc.SSFEventStream) response {
	deliveryEndpoint := stream.DeliveryEndpoint
	if stream.DeliveryMethod == goidc.SSFDeliveryMethodPoll {
		deliveryEndpoint = ctx.BaseURL() + ctx.SSFPollingEndpoint + "/" + stream.ID
	}
	var inactivityTimeout int
	if ctx.SSFInactivityTimeoutSecs != 0 {
		inactivityTimeout = stream.ExpiresAtTimestamp - timeutil.TimestampNow()
	}
	return response{
		ID:              stream.ID,
		Issuer:          ctx.Issuer(),
		Audience:        stream.Audiences,
		EventsSupported: stream.EventsSupported,
		EventsRequested: stream.EventsRequested,
		EventsDelivered: stream.EventsDelivered,
		Delivery: delivery{
			Method:   stream.DeliveryMethod,
			Endpoint: deliveryEndpoint,
		},
		Description:             stream.Description,
		MinVerificationInterval: ctx.SSFMinVerificationInterval,
		InactivityTimeout:       inactivityTimeout,
	}
}

func intersection(a, b []goidc.SSFEventType) []goidc.SSFEventType {
	result := make([]goidc.SSFEventType, 0, min(len(a), len(b)))
	for _, event := range a {
		if slices.Contains(b, event) {
			result = append(result, event)
		}
	}
	return result
}

func pollEvents(ctx oidc.Context, streamID string, req requestPollEvents) (responsePollEvents, error) {
	_, stream, err := receiverAndEventStream(ctx, streamID)
	if err != nil {
		return responsePollEvents{}, err
	}

	if stream.DeliveryMethod != goidc.SSFDeliveryMethodPoll {
		return responsePollEvents{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "stream is not configured for polling")
	}

	if req.Acknowledgements != nil {
		if err := ctx.SSFAcknowledgeEvents(streamID, req.Acknowledgements, goidc.SSFAcknowledgementOptions{
			ReturnImmediately: req.ReturnImmediately,
		}); err != nil {
			return responsePollEvents{}, err
		}
	}

	if req.Errors != nil {
		if err := ctx.SSFAcknowledgeErrors(streamID, req.Errors, goidc.SSFAcknowledgementOptions{
			ReturnImmediately: req.ReturnImmediately,
		}); err != nil {
			return responsePollEvents{}, err
		}
	}

	// [RFC 8936 §2.2] If maxEvents is 0, no events should be returned.
	if req.MaxEvents != nil && *req.MaxEvents == 0 {
		return responsePollEvents{}, nil
	}

	events, err := ctx.SSFPollEvents(streamID, goidc.SSFPollOptions{
		MaxEvents:         req.MaxEvents,
		ReturnImmediately: req.ReturnImmediately,
	})
	if err != nil {
		return responsePollEvents{}, err
	}

	sets := make(map[string]string, len(events.Events))
	for _, event := range events.Events {
		set, err := signEvent(ctx, stream, event)
		if err != nil {
			return responsePollEvents{}, goidc.WrapError(goidc.ErrorCodeInternalError, "internal server error", err)
		}
		sets[event.JWTID] = set
	}
	return responsePollEvents{
		SecurityEventTokens: sets,
		MoreAvailable:       events.MoreAvailable,
	}, nil
}

func signEvent(ctx oidc.Context, stream *goidc.SSFEventStream, event goidc.SSFEvent) (string, error) {
	token := securityEventToken{
		Issuer:      ctx.Issuer(),
		JWTID:       event.JWTID,
		Audience:    stream.Audiences,
		IssuedAt:    timeutil.TimestampNow(),
		Transaction: event.Transaction,
		Subject:     event.Subject,
		Events:      map[goidc.SSFEventType]any{event.Type: event.Claims},
	}

	opts := (&jose.SignerOptions{}).WithType(jwtTypeSecurityEvent)
	return ctx.SSFSign(token, opts)
}

func createVerificationEvent(ctx oidc.Context, req requestVerificationEvent) error {
	_, stream, err := receiverAndEventStream(ctx, req.StreamID)
	if err != nil {
		return err
	}

	return ctx.SSFTriggerVerificationEvent(stream.ID, goidc.SSFStreamVerificationOptions{
		State: req.State,
	})
}

func eventsSupported(ctx oidc.Context, receiver goidc.SSFReceiver) []goidc.SSFEventType {
	events := ctx.SSFEventsSupported
	if receiver.EventsSupported != nil {
		events = receiver.EventsSupported
	}
	return events
}

func receiverAndEventStream(ctx oidc.Context, id string) (goidc.SSFReceiver, *goidc.SSFEventStream, error) {
	receiver, err := ctx.SSFAuthenticatedReceiver()
	if err != nil {
		return goidc.SSFReceiver{}, nil, err
	}

	stream, err := ctx.SSFEventStream(id)
	if err != nil {
		return goidc.SSFReceiver{}, nil, err
	}

	if stream.ReceiverID != receiver.ID {
		return goidc.SSFReceiver{}, nil, goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied", errors.New("stream not owned by receiver"))
	}

	if ctx.SSFInactivityTimeoutSecs != 0 {
		stream.ExpiresAtTimestamp = timeutil.TimestampNow() + ctx.SSFInactivityTimeoutSecs
		if err := ctx.SSFUpdateEventStream(stream); err != nil {
			return goidc.SSFReceiver{}, nil, err
		}
	}

	if stream.ExpiresAtTimestamp != 0 && stream.ExpiresAtTimestamp < timeutil.TimestampNow() {
		return goidc.SSFReceiver{}, nil, goidc.NewError(goidc.ErrorCodeInvalidRequest, "stream has expired")
	}

	return receiver, stream, nil
}
