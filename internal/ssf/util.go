package ssf

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
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
		return fmt.Errorf("could not load the event stream %q: %w", streamID, err)
	}

	// Return an error if the stream did not subscribe to the event type and the event is not a verification event.
	if !slices.Contains(stream.EventsDelivered, event.Type) && (!ctx.SSFIsVerificationEnabled || event.Type != goidc.SSFEventTypeVerification) {
		return fmt.Errorf("stream did not subscribe to event type %s", event.Type)
	}

	if stream.Status != goidc.SSFEventStreamStatusEnabled {
		return nil
	}

	// Ensure the event has a JWTID.
	if event.JWTID == "" {
		event.JWTID = ctx.JWTID()
	}

	if event.Claims == nil {
		event.Claims = make(map[string]any)
	}

	switch stream.DeliveryMethod {
	case goidc.SSFDeliveryMethodPush:
		return pushEvent(ctx, stream, event)
	case goidc.SSFDeliveryMethodPoll:
		if err := ctx.SSFSaveEvent(streamID, event); err != nil {
			return fmt.Errorf("could not save the security event for polling delivery: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported SSF delivery method %q", stream.DeliveryMethod)
	}
}

func pushEvent(ctx oidc.Context, stream *goidc.SSFEventStream, event goidc.SSFEvent) error {
	set, err := signEvent(ctx, stream, event)
	if err != nil {
		return fmt.Errorf("could not sign the security event token: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx.Context(), http.MethodPost, stream.DeliveryEndpoint, strings.NewReader(set))
	if err != nil {
		return fmt.Errorf("could not create the event push request: %w", err)
	}
	req.Header.Set("Content-Type", contentTypeSecurityEvent)
	if stream.AuthorizationHeader != "" {
		req.Header.Set("Authorization", stream.AuthorizationHeader)
	}

	resp, err := ctx.SSFHTTPClient().Do(req)
	if err != nil {
		return fmt.Errorf("could not send the event push request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		return fmt.Errorf("sending the event push request returned status %d", resp.StatusCode)
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

	if streams, _ := ctx.SSFEventStreams(receiver.ID); !ctx.SSFMultipleStreamsPerReceiverIsEnabled && len(streams) > 0 {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("multiple streams per receiver are not allowed")).WithStatusCode(http.StatusConflict)
	}

	// [SSF 1.0 §8.1.1.1] Default to poll delivery when unspecified.
	if req.Delivery.Method == "" {
		req.Delivery.Method = goidc.SSFDeliveryMethodPoll
	}

	audiences := receiver.Audiences
	if len(audiences) == 0 {
		audiences = []string{receiver.ID}
	}
	stream := &goidc.SSFEventStream{
		ID:              ctx.SSFEventStreamID(),
		ReceiverID:      receiver.ID,
		Audiences:       audiences,
		Status:          goidc.SSFEventStreamStatusEnabled,
		EventsSupported: ctx.SSFEventTypes,
		EventsRequested: req.EventsRequested,
		EventsDelivered: intersection(ctx.SSFEventTypes, req.EventsRequested),
		DeliveryMethod:  req.Delivery.Method,
		CreatedAt:       timeutil.TimestampNow(),
	}
	if req.Delivery.Endpoint != nil {
		stream.DeliveryEndpoint = *req.Delivery.Endpoint
	}
	if req.Delivery.AuthorizationHeader != nil {
		stream.AuthorizationHeader = *req.Delivery.AuthorizationHeader
	}
	if req.Description != nil {
		stream.Description = *req.Description
	}
	if err := validateStream(ctx, stream); err != nil {
		return response{}, err
	}

	if err := ctx.SSFCreateEventStream(stream); err != nil {
		return response{}, fmt.Errorf("could not create the event stream: %w", err)
	}

	return toResponse(ctx, stream), nil
}

func updateStream(ctx oidc.Context, req request) (response, error) {
	stream, err := authorizedStream(ctx, req.ID)
	if err != nil {
		return response{}, err
	}

	// [SSF 1.0 §8.1.1.1] Default to poll delivery when unspecified.
	if req.Delivery.Method == "" {
		req.Delivery.Method = goidc.SSFDeliveryMethodPoll
	}

	stream.EventsRequested = req.EventsRequested
	stream.EventsDelivered = intersection(ctx.SSFEventTypes, req.EventsRequested)
	stream.DeliveryMethod = req.Delivery.Method
	if req.Delivery.Endpoint != nil {
		stream.DeliveryEndpoint = *req.Delivery.Endpoint
	}
	if req.Delivery.AuthorizationHeader != nil {
		stream.AuthorizationHeader = *req.Delivery.AuthorizationHeader
	}
	if req.Description != nil {
		stream.Description = *req.Description
	}
	if err := validateStream(ctx, stream); err != nil {
		return response{}, err
	}

	if err := ctx.SSFUpdateEventStream(stream); err != nil {
		return response{}, fmt.Errorf("could not update the event stream: %w", err)
	}

	return toResponse(ctx, stream), nil

}

func patchStream(ctx oidc.Context, req request) (response, error) {
	stream, err := authorizedStream(ctx, req.ID)
	if err != nil {
		return response{}, err
	}

	if req.EventsRequested != nil {
		stream.EventsRequested = req.EventsRequested
		stream.EventsDelivered = intersection(ctx.SSFEventTypes, req.EventsRequested)
	}

	if req.Delivery.Method != "" {
		stream.DeliveryMethod = req.Delivery.Method
	}

	if req.Delivery.Endpoint != nil {
		stream.DeliveryEndpoint = *req.Delivery.Endpoint
	}

	if req.Delivery.AuthorizationHeader != nil {
		stream.AuthorizationHeader = *req.Delivery.AuthorizationHeader
	}

	if req.Description != nil {
		stream.Description = *req.Description
	}

	if err := validateStream(ctx, stream); err != nil {
		return response{}, err
	}

	if err := ctx.SSFUpdateEventStream(stream); err != nil {
		return response{}, fmt.Errorf("could not update the event stream: %w", err)
	}

	return toResponse(ctx, stream), nil
}

func fetchStream(ctx oidc.Context, id string) (response, error) {
	stream, err := authorizedStream(ctx, id)
	if err != nil {
		return response{}, err
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
		return []response{}, fmt.Errorf("could not load the event streams for receiver %q: %w", receiver.ID, err)
	}

	responses := make([]response, 0, len(streams))
	for _, stream := range streams {
		responses = append(responses, toResponse(ctx, stream))
	}
	return responses, nil
}

func deleteStream(ctx oidc.Context, id string) error {
	stream, err := authorizedStream(ctx, id)
	if err != nil {
		return err
	}

	if err := ctx.SSFDeleteEventStream(stream.ID); err != nil {
		return fmt.Errorf("could not delete the event stream: %w", err)
	}
	return nil
}

func fetchStreamStatus(ctx oidc.Context, id string) (responseStatus, error) {
	stream, err := authorizedStream(ctx, id)
	if err != nil {
		return responseStatus{}, err
	}

	return responseStatus{
		ID:           stream.ID,
		Status:       stream.Status,
		StatusReason: stream.StatusReason,
	}, nil
}

func updateStreamStatus(ctx oidc.Context, req requestStatus) (responseStatus, error) {
	stream, err := authorizedStream(ctx, req.ID)
	if err != nil {
		return responseStatus{}, err
	}

	stream.Status = req.Status
	stream.StatusReason = req.StatusReason
	if err := ctx.SSFUpdateEventStream(stream); err != nil {
		return responseStatus{}, fmt.Errorf("could not update the event stream status: %w", err)
	}

	return responseStatus{
		ID:           stream.ID,
		Status:       stream.Status,
		StatusReason: stream.StatusReason,
	}, nil
}

func addSubject(ctx oidc.Context, req requestSubject) error {
	stream, err := authorizedStream(ctx, req.StreamID)
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
	if err := ctx.SSFAddSubject(stream.ID, req.Subject, goidc.SSFSubjectOptions{
		Verified: verified,
	}); err != nil {
		return fmt.Errorf("could not add the subject to the event stream: %w", err)
	}
	return nil
}

func removeSubject(ctx oidc.Context, req requestSubject) error {
	if _, err := authorizedStream(ctx, req.StreamID); err != nil {
		return err
	}

	if err := validateSubject(ctx, req.Subject); err != nil {
		return err
	}

	if err := ctx.SSFRemoveSubject(req.StreamID, req.Subject); err != nil {
		return fmt.Errorf("could not remove the subject from the event stream: %w", err)
	}
	return nil
}

func validateStream(ctx oidc.Context, stream *goidc.SSFEventStream) error {
	if !slices.Contains(ctx.SSFDeliveryMethods, stream.DeliveryMethod) {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("delivery method %q is not supported", stream.DeliveryMethod))
	}

	if stream.DeliveryMethod == goidc.SSFDeliveryMethodPush {
		if stream.DeliveryEndpoint == "" {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("delivery endpoint_url is required for push delivery"))
		}

		if _, err := url.Parse(stream.DeliveryEndpoint); err != nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("delivery endpoint_url is invalid: %w", err))
		}
	}

	if stream.DeliveryMethod == goidc.SSFDeliveryMethodPoll {
		if stream.DeliveryEndpoint != "" {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("delivery endpoint_url is not allowed for poll delivery"))
		}

		if stream.AuthorizationHeader != "" {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("authorization_header is not allowed for poll delivery"))
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

func validateSubject(ctx oidc.Context, sub goidc.SSFSubject) error { //nolint:unparam
	allowed, ok := subjectAllowedFields[sub.Format]
	if !ok {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("subject format %q is not supported", sub.Format))
	}

	// Check disallowed fields are empty.
	if !allowed.id && sub.ID != "" {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("id is not allowed for %s subject format", sub.Format))
	}
	if !allowed.email && sub.Email != "" {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("email is not allowed for %s subject format", sub.Format))
	}
	if !allowed.phone && sub.Phone != "" {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("phone_number is not allowed for %s subject format", sub.Format))
	}
	if !allowed.uri && sub.URI != "" {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("uri is not allowed for %s subject format", sub.Format))
	}
	if !allowed.iss && sub.Iss != "" {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("iss is not allowed for %s subject format", sub.Format))
	}
	if !allowed.sub && sub.Sub != "" {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("sub is not allowed for %s subject format", sub.Format))
	}
	if !allowed.url && sub.URL != "" {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("url is not allowed for %s subject format", sub.Format))
	}
	if !allowed.jti && sub.JTI != "" {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("jti is not allowed for %s subject format", sub.Format))
	}
	if !allowed.assertionID && sub.AssertionID != "" {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("assertion_id is not allowed for %s subject format", sub.Format))
	}
	if !allowed.issuer && sub.Issuer != "" {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("issuer is not allowed for %s subject format", sub.Format))
	}
	if !allowed.ipAddresses && sub.IPAddresses != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("ip-addresses is not allowed for %s subject format", sub.Format))
	}
	if !allowed.identifiers && sub.Identifiers != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("identifiers is not allowed for %s subject format", sub.Format))
	}
	if !allowed.user && sub.User != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("user is not allowed for %s subject format", sub.Format))
	}
	if !allowed.tenant && sub.Tenant != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("tenant is not allowed for %s subject format", sub.Format))
	}
	if !allowed.device && sub.Device != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("device is not allowed for %s subject format", sub.Format))
	}
	if !allowed.session && sub.Session != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("session is not allowed for %s subject format", sub.Format))
	}
	if !allowed.orgUnit && sub.OrganizationalUnit != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("org_unit is not allowed for %s subject format", sub.Format))
	}
	if !allowed.application && sub.Application != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("application is not allowed for %s subject format", sub.Format))
	}
	if !allowed.group && sub.Group != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("group is not allowed for %s subject format", sub.Format))
	}
	if !allowed.additionalProperties && sub.AdditionalProperties != nil {
		return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("additional properties are not allowed for %s subject format", sub.Format))
	}

	// Format-specific required field validation.
	switch sub.Format {
	case goidc.SSFSubjectFormatOpaque:
		if sub.ID == "" {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("id is required for opaque subject format"))
		}
	case goidc.SSFSubjectFormatEmail:
		if sub.Email == "" {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("email is required for email subject format"))
		}
	case goidc.SSFSubjectFormatPhoneNumber:
		if sub.Phone == "" {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("phone_number is required for phone_number subject format"))
		}
	case goidc.SSFSubjectFormatAccount, goidc.SSFSubjectFormatURI:
		if sub.URI == "" {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("uri is required for %s subject format", sub.Format))
		}
	case goidc.SSFSubjectFormatIssuerSubject:
		if sub.Iss == "" {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("iss is required for iss_sub subject format"))
		}
		if sub.Sub == "" {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("sub is required for iss_sub subject format"))
		}
	case goidc.SSFSubjectDecentralizedIdentifier:
		if sub.URL == "" {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("url is required for did subject format"))
		}
	case goidc.SSFSubjectJWTID:
		if sub.JTI == "" {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("jti is required for jwt_id subject format"))
		}
		if sub.Iss == "" {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("iss is required for jwt_id subject format"))
		}
	case goidc.SSFSubjectSAMLAssertionID:
		if sub.AssertionID == "" {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("assertion_id is required for saml_assertion_id subject format"))
		}
		if sub.Issuer == "" {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("issuer is required for saml_assertion_id subject format"))
		}
	case goidc.SSFSubjectIPAddresses:
		if len(sub.IPAddresses) == 0 {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("ip-addresses is required for ip-addresses subject format"))
		}
	case goidc.SSFSubjectFormatAliases:
		if len(sub.Identifiers) == 0 {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("identifiers is required for aliases subject format"))
		}
		for _, member := range sub.Identifiers {
			// [RFC 9493 §3.2.8] A member of an alias must not be an alias.
			if member.Format == goidc.SSFSubjectFormatAliases {
				return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("aliases cannot contain aliases"))
			}
			if err := validateSubject(ctx, member); err != nil {
				return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", fmt.Errorf("alias identifier is invalid: %w", err))
			}
		}
	case goidc.SSFSubjectFormatComplex:
		// [SSF 1.0 §3.3] A complex subject must contain at least one field.
		if sub.User == nil && sub.Tenant == nil && sub.Device == nil && sub.Session == nil &&
			sub.OrganizationalUnit == nil && sub.Application == nil && sub.Group == nil {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("at least one member is required for complex subject format"))
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
		inactivityTimeout = stream.ExpiresAt - timeutil.TimestampNow()
	}
	return response{
		ID:              stream.ID,
		Issuer:          ctx.Issuer(),
		Audience:        stream.Audiences,
		EventsSupported: stream.EventsSupported,
		EventsRequested: stream.EventsRequested,
		EventsDelivered: stream.EventsDelivered,
		Delivery: responseDelivery{
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
	stream, err := authorizedStream(ctx, streamID)
	if err != nil {
		return responsePollEvents{}, err
	}

	if stream.DeliveryMethod != goidc.SSFDeliveryMethodPoll {
		return responsePollEvents{}, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("stream is not configured for polling"))
	}

	if req.Acknowledgements != nil {
		if err := ctx.SSFAcknowledgeEvents(streamID, req.Acknowledgements, goidc.SSFAcknowledgementOptions{
			ReturnImmediately: req.ReturnImmediately,
		}); err != nil {
			return responsePollEvents{}, fmt.Errorf("could not acknowledge the polled security events: %w", err)
		}
	}

	if req.Errors != nil {
		if err := ctx.SSFAcknowledgeErrors(streamID, req.Errors, goidc.SSFAcknowledgementOptions{
			ReturnImmediately: req.ReturnImmediately,
		}); err != nil {
			return responsePollEvents{}, fmt.Errorf("could not acknowledge the polled security event errors: %w", err)
		}
	}

	// [RFC 8936 §2.2] If maxEvents is 0, no events should be returned.
	if req.MaxEvents != nil && *req.MaxEvents == 0 {
		return responsePollEvents{
			SecurityEventTokens: make(map[string]string),
		}, nil
	}

	events, err := ctx.SSFPollEvents(streamID, goidc.SSFPollOptions{
		MaxEvents:         req.MaxEvents,
		ReturnImmediately: req.ReturnImmediately,
	})
	if err != nil {
		return responsePollEvents{}, fmt.Errorf("could not poll the pending security events: %w", err)
	}

	sets := make(map[string]string, len(events.Events))
	for _, event := range events.Events {
		set, err := signEvent(ctx, stream, event)
		if err != nil {
			return responsePollEvents{}, fmt.Errorf("could not sign the polled security event token: %w", err)
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

func scheduleVerificationEvent(ctx oidc.Context, req requestVerificationEvent) error {
	stream, err := authorizedStream(ctx, req.StreamID)
	if err != nil {
		return err
	}

	if ctx.SSFMinVerificationInterval != 0 {
		if stream.VerifiedAt != 0 && stream.VerifiedAt+ctx.SSFMinVerificationInterval > timeutil.TimestampNow() {
			return goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("verification event cannot be triggered within the minimum verification interval")).WithStatusCode(http.StatusTooManyRequests)
		}
		stream.VerifiedAt = timeutil.TimestampNow()
		if err := ctx.SSFUpdateEventStream(stream); err != nil {
			return fmt.Errorf("could not update the event stream verification timestamp: %w", err)
		}
	}

	if err := ctx.SSFScheduleVerificationEvent(stream.ID, goidc.SSFStreamVerificationOptions{
		State: req.State,
	}); err != nil {
		return fmt.Errorf("could not schedule the verification event: %w", err)
	}
	return nil
}

func authorizedStream(ctx oidc.Context, id string) (*goidc.SSFEventStream, error) {
	receiver, err := ctx.SSFAuthenticatedReceiver()
	if err != nil {
		return nil, err
	}

	if id == "" {
		return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("stream_id is required"))
	}

	stream, err := ctx.SSFEventStream(id)
	if err != nil {
		if errors.Is(err, goidc.ErrNotFound) {
			return nil, goidc.WrapError(goidc.ErrorCodeInvalidRequest, "invalid request", errors.New("stream was not found")).WithStatusCode(http.StatusNotFound)
		}
		return nil, fmt.Errorf("could not load the event stream %q: %w", id, err)
	}

	if stream.ReceiverID != receiver.ID {
		return nil, goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied", errors.New("stream not owned by receiver"))
	}

	if stream.ExpiresAt != 0 && stream.ExpiresAt <= timeutil.TimestampNow() {
		if err := ctx.SSFHandleExpiredEventStream(stream); err != nil {
			return nil, fmt.Errorf("could not handle the expired event stream: %w", err)
		}
		stream.ExpiresAt = 0
		if err := ctx.SSFUpdateEventStream(stream); err != nil {
			return nil, fmt.Errorf("could not clear the expired event stream timeout: %w", err)
		}
	}

	if ctx.SSFInactivityTimeoutSecs != 0 {
		stream.ExpiresAt = timeutil.TimestampNow() + ctx.SSFInactivityTimeoutSecs
		if err := ctx.SSFUpdateEventStream(stream); err != nil {
			return nil, fmt.Errorf("could not update the event stream inactivity timeout: %w", err)
		}
	}

	return stream, nil
}

// compareSubjects compares two [goidc.SSFSubject] according to the subject matching rules.
// [SSF 1.0 §8.1.3.1].
func compareSubjects(a, b *goidc.SSFSubject) bool {
	// If either is nil, they match (undefined field matches anything).
	if a == nil || b == nil {
		return true
	}

	// For simple subjects, two subjects match if they are exactly identical.
	if a.Format != goidc.SSFSubjectFormatComplex && b.Format != goidc.SSFSubjectFormatComplex {
		return reflect.DeepEqual(a, b)
	}

	// For complex subjects, two subjects match if, for all fields in the complex subject
	// (i.e. user, group, device, etc.), at least one of the following statements is true:
	// - Subject 1's field is not defined (nil).
	// - Subject 2's field is not defined (nil).
	// - Subject 1's field is identical to Subject 2's field.
	if !compareSubjects(a.User, b.User) {
		return false
	}
	if !compareSubjects(a.Tenant, b.Tenant) {
		return false
	}
	if !compareSubjects(a.Device, b.Device) {
		return false
	}
	if !compareSubjects(a.Session, b.Session) {
		return false
	}
	if !compareSubjects(a.OrganizationalUnit, b.OrganizationalUnit) {
		return false
	}
	if !compareSubjects(a.Application, b.Application) {
		return false
	}
	if !compareSubjects(a.Group, b.Group) {
		return false
	}

	// For each key present in both maps, values must be identical.
	for key, aVal := range a.AdditionalProperties {
		if bVal, exists := b.AdditionalProperties[key]; exists {
			if !reflect.DeepEqual(aVal, bVal) {
				return false
			}
		}
	}

	return true
}
