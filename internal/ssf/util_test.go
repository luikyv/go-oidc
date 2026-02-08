package ssf

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const testReceiverID = "test_receiver_id"

func TestCompareSubjects(t *testing.T) {
	testCases := []struct {
		name  string
		a, b  goidc.SSFSubject
		match bool
	}{
		{
			name:  "identical email subjects match",
			a:     goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
			b:     goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
			match: true,
		},
		{
			name:  "different email subjects do not match",
			a:     goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user1@example.com"},
			b:     goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user2@example.com"},
			match: false,
		},
		{
			name:  "identical opaque subjects match",
			a:     goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "user123"},
			b:     goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "user123"},
			match: true,
		},
		{
			name:  "different opaque subjects do not match",
			a:     goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "user123"},
			b:     goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "user456"},
			match: false,
		},
		{
			name:  "identical iss_sub subjects match",
			a:     goidc.SSFSubject{Format: goidc.SSFSubjectFormatIssuerSubject, Iss: "https://issuer.com", Sub: "user123"},
			b:     goidc.SSFSubject{Format: goidc.SSFSubjectFormatIssuerSubject, Iss: "https://issuer.com", Sub: "user123"},
			match: true,
		},
		{
			name:  "different formats do not match",
			a:     goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
			b:     goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "user@example.com"},
			match: false,
		},
		{
			name: "complex subjects with matching user field",
			a: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				User:   &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
			},
			b: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				User:   &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
			},
			match: true,
		},
		{
			name: "complex subjects with nil field matches any",
			a: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				User:   &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
			},
			b: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				User:   nil,
			},
			match: true,
		},
		{
			name: "complex subjects with different user fields do not match",
			a: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				User:   &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user1@example.com"},
			},
			b: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				User:   &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user2@example.com"},
			},
			match: false,
		},
		{
			name: "complex subjects with matching multiple fields",
			a: goidc.SSFSubject{
				Format:  goidc.SSFSubjectFormatComplex,
				User:    &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				Session: &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "session123"},
			},
			b: goidc.SSFSubject{
				Format:  goidc.SSFSubjectFormatComplex,
				User:    &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				Session: &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "session123"},
			},
			match: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := compareSubjects(&tc.a, &tc.b)
			if result != tc.match {
				t.Errorf("compareSubjects() = %v, want %v", result, tc.match)
			}
		})
	}
}

func TestCreateStream(t *testing.T) {
	// Given.
	ctx := setUp(t)
	endpoint := "https://receiver.com/events"
	req := request{
		EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
		Delivery: requestDelivery{
			Method:   goidc.SSFDeliveryMethodPush,
			Endpoint: &endpoint,
		},
	}

	// When.
	resp, err := createStream(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error creating the stream: %v", err)
	}

	if resp.ID == "" {
		t.Error("stream ID should not be empty")
	}
	if resp.Issuer != ctx.Issuer() {
		t.Errorf("issuer = %s, want %s", resp.Issuer, ctx.Issuer())
	}
	if len(resp.Audience) != 1 || resp.Audience[0] != testReceiverID {
		t.Errorf("audience = %v, want [%s]", resp.Audience, testReceiverID)
	}
	if resp.Delivery.Method != goidc.SSFDeliveryMethodPush {
		t.Errorf("delivery method = %s, want %s", resp.Delivery.Method, goidc.SSFDeliveryMethodPush)
	}
}

func TestCreateStream_DefaultsToPoll(t *testing.T) {
	// Given.
	ctx := setUp(t)
	req := request{
		EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
		Delivery:        requestDelivery{},
	}

	// When.
	resp, err := createStream(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error creating the stream: %v", err)
	}

	if resp.Delivery.Method != goidc.SSFDeliveryMethodPoll {
		t.Errorf("delivery method = %s, want %s (default)", resp.Delivery.Method, goidc.SSFDeliveryMethodPoll)
	}
}

func TestCreateStream_InvalidDeliveryMethod(t *testing.T) {
	// Given.
	ctx := setUp(t)
	ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{goidc.SSFDeliveryMethodPoll}

	endpoint := "https://receiver.com/events"
	req := request{
		EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
		Delivery: requestDelivery{
			Method:   goidc.SSFDeliveryMethodPush,
			Endpoint: &endpoint,
		},
	}

	// When.
	_, err := createStream(ctx, req)

	// Then.
	if err == nil {
		t.Fatal("expected error for invalid delivery method")
	}
}

func TestCreateStream_PushRequiresEndpoint(t *testing.T) {
	// Given.
	ctx := setUp(t)
	req := request{
		EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
		Delivery: requestDelivery{
			Method: goidc.SSFDeliveryMethodPush,
		},
	}

	// When.
	_, err := createStream(ctx, req)

	// Then.
	if err == nil {
		t.Fatal("expected error when push delivery has no endpoint")
	}
}

func TestCreateStream_PollDisallowsEndpoint(t *testing.T) {
	// Given.
	ctx := setUp(t)
	endpoint := "https://receiver.com/events"
	req := request{
		EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
		Delivery: requestDelivery{
			Method:   goidc.SSFDeliveryMethodPoll,
			Endpoint: &endpoint,
		},
	}

	// When.
	_, err := createStream(ctx, req)

	// Then.
	if err == nil {
		t.Fatal("expected error when poll delivery has endpoint")
	}
}

func TestValidateSubject(t *testing.T) {
	ctx := setUp(t)

	testCases := []struct {
		name    string
		subject goidc.SSFSubject
		wantErr bool
	}{
		// Opaque format.
		{
			name:    "valid opaque subject",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "user123"},
			wantErr: false,
		},
		{
			name:    "opaque subject missing id",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque},
			wantErr: true,
		},
		{
			name:    "opaque subject with disallowed email field",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "user123", Email: "user@example.com"},
			wantErr: true,
		},
		// Email format.
		{
			name:    "valid email subject",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
			wantErr: false,
		},
		{
			name:    "email subject missing email",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail},
			wantErr: true,
		},
		{
			name:    "email subject with disallowed id field",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com", ID: "user123"},
			wantErr: true,
		},
		// Issuer-subject format.
		{
			name:    "valid iss_sub subject",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatIssuerSubject, Iss: "https://issuer.com", Sub: "user123"},
			wantErr: false,
		},
		{
			name:    "iss_sub subject missing iss",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatIssuerSubject, Sub: "user123"},
			wantErr: true,
		},
		{
			name:    "iss_sub subject missing sub",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatIssuerSubject, Iss: "https://issuer.com"},
			wantErr: true,
		},
		{
			name: "valid complex subject with user",
			subject: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				User:   &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
			},
			wantErr: false,
		},
		{
			name: "valid complex subject with multiple fields",
			subject: goidc.SSFSubject{
				Format:  goidc.SSFSubjectFormatComplex,
				User:    &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				Session: &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "session123"},
			},
			wantErr: false,
		},
		{
			name:    "complex subject with no fields",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatComplex},
			wantErr: true,
		},
		{
			name: "complex subject with invalid nested subject",
			subject: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				User:   &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail}, // missing email
			},
			wantErr: true,
		},
		{
			name: "valid aliases subject",
			subject: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatAliases,
				Identifiers: []goidc.SSFSubject{
					{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
					{Format: goidc.SSFSubjectFormatOpaque, ID: "user123"},
				},
			},
			wantErr: false,
		},
		{
			name:    "aliases subject with no identifiers",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatAliases},
			wantErr: true,
		},
		{
			name: "aliases subject containing alias (not allowed)",
			subject: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatAliases,
				Identifiers: []goidc.SSFSubject{
					{Format: goidc.SSFSubjectFormatAliases, Identifiers: []goidc.SSFSubject{}},
				},
			},
			wantErr: true,
		},
		// Invalid format.
		{
			name:    "invalid subject format",
			subject: goidc.SSFSubject{Format: "invalid_format"},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSubject(ctx, tc.subject)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateSubject() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestPollEvents(t *testing.T) {
	// Given.
	ctx := setUp(t)
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	// Save some events.
	for i := range 5 {
		event := goidc.SSFEvent{
			JWTID:   fmt.Sprintf("jti_%d", i),
			Type:    goidc.SSFEventTypeCAEPSessionRevoked,
			Subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
		}
		if err := ctx.SSFSaveEvent(stream.ID, event); err != nil {
			t.Fatalf("error saving event: %v", err)
		}
	}

	// When.
	maxEvents := 3
	resp, err := pollEvents(ctx, stream.ID, requestPollEvents{MaxEvents: &maxEvents})

	// Then.
	if err != nil {
		t.Fatalf("unexpected error polling events: %v", err)
	}

	if len(resp.SecurityEventTokens) != 3 {
		t.Errorf("got %d events, want 3", len(resp.SecurityEventTokens))
	}
	if !resp.MoreAvailable {
		t.Error("moreAvailable should be true")
	}
}

func TestPollEvents_Acknowledgement(t *testing.T) {
	// Given.
	ctx := setUp(t)
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	// Save events.
	for i := range 3 {
		event := goidc.SSFEvent{
			JWTID:   fmt.Sprintf("jti_%d", i),
			Type:    goidc.SSFEventTypeCAEPSessionRevoked,
			Subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
		}
		if err := ctx.SSFSaveEvent(stream.ID, event); err != nil {
			t.Fatalf("error saving event: %v", err)
		}
	}

	// When - poll with acknowledgement.
	_, err := pollEvents(ctx, stream.ID, requestPollEvents{
		Acknowledgements: []string{"jti_0", "jti_1"},
	})

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Poll again to verify events were acknowledged.
	resp, _ := pollEvents(ctx, stream.ID, requestPollEvents{})
	if len(resp.SecurityEventTokens) != 1 {
		t.Errorf("got %d events after ack, want 1", len(resp.SecurityEventTokens))
	}
}

func TestPollEvents_MaxEventsZero(t *testing.T) {
	// Given.
	ctx := setUp(t)
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	event := goidc.SSFEvent{
		JWTID:   "jti_a",
		Type:    goidc.SSFEventTypeCAEPSessionRevoked,
		Subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
	}
	if err := ctx.SSFSaveEvent(stream.ID, event); err != nil {
		t.Fatalf("error saving event: %v", err)
	}

	// When - maxEvents = 0 means no events should be returned.
	maxEvents := 0
	resp, err := pollEvents(ctx, stream.ID, requestPollEvents{MaxEvents: &maxEvents})

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.SecurityEventTokens) != 0 {
		t.Errorf("got %d events, want 0 (maxEvents=0)", len(resp.SecurityEventTokens))
	}
}

func TestPollEvents_WrongDeliveryMethod(t *testing.T) {
	// Given.
	ctx := setUp(t)
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPush)

	// When.
	_, err := pollEvents(ctx, stream.ID, requestPollEvents{})

	// Then.
	if err == nil {
		t.Error("expected error when polling push stream")
	}
}

func TestValidateSubject_AllFormats(t *testing.T) {
	ctx := setUp(t)

	testCases := []struct {
		name    string
		subject goidc.SSFSubject
		wantErr bool
	}{
		// Phone number format.
		{
			name:    "valid phone subject",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatPhoneNumber, Phone: "+1234567890"},
			wantErr: false,
		},
		{
			name:    "phone subject missing phone",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatPhoneNumber},
			wantErr: true,
		},
		{
			name:    "phone subject with disallowed email",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatPhoneNumber, Phone: "+1234567890", Email: "user@example.com"},
			wantErr: true,
		},
		// Account format.
		{
			name:    "valid account subject",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatAccount, URI: "acct:user@example.com"},
			wantErr: false,
		},
		{
			name:    "account subject missing uri",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatAccount},
			wantErr: true,
		},
		// URI format.
		{
			name:    "valid uri subject",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatURI, URI: "https://example.com/users/123"},
			wantErr: false,
		},
		{
			name:    "uri subject missing uri",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatURI},
			wantErr: true,
		},
		// DID format.
		{
			name:    "valid did subject",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectDecentralizedIdentifier, URL: "did:example:123"},
			wantErr: false,
		},
		{
			name:    "did subject missing url",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectDecentralizedIdentifier},
			wantErr: true,
		},
		// JWT ID format.
		{
			name:    "valid jwt_id subject",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectJWTID, JTI: "token123", Iss: "https://issuer.com"},
			wantErr: false,
		},
		{
			name:    "jwt_id subject missing jti",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectJWTID, Iss: "https://issuer.com"},
			wantErr: true,
		},
		{
			name:    "jwt_id subject missing iss",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectJWTID, JTI: "token123"},
			wantErr: true,
		},
		// SAML assertion ID format.
		{
			name:    "valid saml subject",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectSAMLAssertionID, AssertionID: "assertion123", Issuer: "https://idp.example.com"},
			wantErr: false,
		},
		{
			name:    "saml subject missing assertion_id",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectSAMLAssertionID, Issuer: "https://idp.example.com"},
			wantErr: true,
		},
		{
			name:    "saml subject missing issuer",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectSAMLAssertionID, AssertionID: "assertion123"},
			wantErr: true,
		},
		// IP addresses format.
		{
			name:    "valid ip_addresses subject",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectIPAddresses, IPAddresses: []string{"192.168.1.1", "10.0.0.1"}},
			wantErr: false,
		},
		{
			name:    "ip_addresses subject empty",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectIPAddresses, IPAddresses: []string{}},
			wantErr: true,
		},
		{
			name:    "ip_addresses subject nil",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectIPAddresses},
			wantErr: true,
		},
		// Complex format with all nested fields.
		{
			name: "complex subject with tenant",
			subject: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				Tenant: &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "tenant123"},
			},
			wantErr: false,
		},
		{
			name: "complex subject with device",
			subject: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				Device: &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "device123"},
			},
			wantErr: false,
		},
		{
			name: "complex subject with org_unit",
			subject: goidc.SSFSubject{
				Format:             goidc.SSFSubjectFormatComplex,
				OrganizationalUnit: &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "orgunit123"},
			},
			wantErr: false,
		},
		{
			name: "complex subject with application",
			subject: goidc.SSFSubject{
				Format:      goidc.SSFSubjectFormatComplex,
				Application: &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "app123"},
			},
			wantErr: false,
		},
		{
			name: "complex subject with group",
			subject: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				Group:  &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "group123"},
			},
			wantErr: false,
		},
		{
			name: "complex subject with additional properties",
			subject: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				User:   &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				AdditionalProperties: map[string]goidc.SSFSubject{
					"custom": {Format: goidc.SSFSubjectFormatOpaque, ID: "custom123"},
				},
			},
			wantErr: false,
		},
		{
			name: "complex subject with invalid additional property",
			subject: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				User:   &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				AdditionalProperties: map[string]goidc.SSFSubject{
					"custom": {Format: goidc.SSFSubjectFormatEmail}, // missing email
				},
			},
			wantErr: true,
		},
		// Disallowed field combinations.
		{
			name:    "email subject with disallowed phone",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com", Phone: "+123"},
			wantErr: true,
		},
		{
			name:    "opaque subject with disallowed uri",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "user123", URI: "https://example.com"},
			wantErr: true,
		},
		{
			name:    "email subject with disallowed iss",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com", Iss: "https://issuer.com"},
			wantErr: true,
		},
		{
			name:    "email subject with disallowed sub",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com", Sub: "user123"},
			wantErr: true,
		},
		{
			name:    "email subject with disallowed url",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com", URL: "https://example.com"},
			wantErr: true,
		},
		{
			name:    "email subject with disallowed jti",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com", JTI: "token123"},
			wantErr: true,
		},
		{
			name:    "email subject with disallowed assertion_id",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com", AssertionID: "assertion123"},
			wantErr: true,
		},
		{
			name:    "email subject with disallowed issuer",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com", Issuer: "https://idp.com"},
			wantErr: true,
		},
		{
			name:    "email subject with disallowed ip_addresses",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com", IPAddresses: []string{"192.168.1.1"}},
			wantErr: true,
		},
		{
			name:    "email subject with disallowed identifiers",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com", Identifiers: []goidc.SSFSubject{}},
			wantErr: true,
		},
		{
			name: "email subject with disallowed user",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com",
				User: &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "user123"}},
			wantErr: true,
		},
		{
			name: "email subject with disallowed tenant",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com",
				Tenant: &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "tenant123"}},
			wantErr: true,
		},
		{
			name: "email subject with disallowed device",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com",
				Device: &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "device123"}},
			wantErr: true,
		},
		{
			name: "email subject with disallowed session",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com",
				Session: &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "session123"}},
			wantErr: true,
		},
		{
			name: "email subject with disallowed org_unit",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com",
				OrganizationalUnit: &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "orgunit123"}},
			wantErr: true,
		},
		{
			name: "email subject with disallowed application",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com",
				Application: &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "app123"}},
			wantErr: true,
		},
		{
			name: "email subject with disallowed group",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com",
				Group: &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "group123"}},
			wantErr: true,
		},
		{
			name: "email subject with disallowed additional_properties",
			subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com",
				AdditionalProperties: map[string]goidc.SSFSubject{}},
			wantErr: true,
		},
		// Aliases with invalid member.
		{
			name: "aliases with invalid member",
			subject: goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatAliases,
				Identifiers: []goidc.SSFSubject{
					{Format: goidc.SSFSubjectFormatEmail}, // missing email
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSubject(ctx, tc.subject)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateSubject() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestUpdateStream(t *testing.T) {
	// Given.
	ctx := setUp(t)
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	newEndpoint := "https://receiver.com/new-events"
	authHeader := "Bearer token123"
	description := "Updated stream"
	updateReq := request{
		ID:              stream.ID,
		EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPCredentialChange},
		Delivery: requestDelivery{
			Method:              goidc.SSFDeliveryMethodPush,
			Endpoint:            &newEndpoint,
			AuthorizationHeader: &authHeader,
		},
		Description: &description,
	}

	// When.
	resp, err := updateStream(ctx, updateReq)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Delivery.Method != goidc.SSFDeliveryMethodPush {
		t.Errorf("delivery method = %s, want %s", resp.Delivery.Method, goidc.SSFDeliveryMethodPush)
	}
	if resp.Description != description {
		t.Errorf("description = %s, want %s", resp.Description, description)
	}
}

func TestUpdateStream_InvalidStreamID(t *testing.T) {
	ctx := setUp(t)

	_, err := updateStream(ctx, request{ID: "nonexistent"})
	if err == nil {
		t.Error("expected error for nonexistent stream")
	}
}

func TestUpdateStream_EmptyStreamID(t *testing.T) {
	ctx := setUp(t)

	_, err := updateStream(ctx, request{ID: ""})
	if err == nil {
		t.Error("expected error for empty stream ID")
	}
}

func TestPatchStream(t *testing.T) {
	// Given.
	ctx := setUp(t)
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	description := "Patched description"
	patchReq := request{
		ID:          stream.ID,
		Description: &description,
	}

	// When.
	resp, err := patchStream(ctx, patchReq)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Description != description {
		t.Errorf("description = %s, want %s", resp.Description, description)
	}
	// Verify original delivery method is preserved.
	if resp.Delivery.Method != goidc.SSFDeliveryMethodPoll {
		t.Errorf("delivery method = %s, want %s", resp.Delivery.Method, goidc.SSFDeliveryMethodPoll)
	}
}

func TestPatchStream_PartialUpdate(t *testing.T) {
	// Given.
	ctx := setUp(t)
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	// When - only update events requested.
	patchReq := request{
		ID:              stream.ID,
		EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPCredentialChange},
	}
	resp, err := patchStream(ctx, patchReq)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.EventsRequested) != 1 || resp.EventsRequested[0] != goidc.SSFEventTypeCAEPCredentialChange {
		t.Errorf("events_requested = %v, want [%s]", resp.EventsRequested, goidc.SSFEventTypeCAEPCredentialChange)
	}
}

func TestFetchStream(t *testing.T) {
	// Given.
	ctx := setUp(t)
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	// When.
	resp, err := fetchStream(ctx, stream.ID)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ID != stream.ID {
		t.Errorf("stream ID = %s, want %s", resp.ID, stream.ID)
	}
}

func TestFetchStream_NotFound(t *testing.T) {
	ctx := setUp(t)

	_, err := fetchStream(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent stream")
	}
}

func TestFetchStreams(t *testing.T) {
	// Given.
	ctx := setUp(t)
	ctx.SSFMultipleStreamsPerReceiverIsEnabled = true
	_ = createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)
	_ = createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	// When.
	streams, err := fetchStreams(ctx)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(streams) != 2 {
		t.Errorf("got %d streams, want 2", len(streams))
	}
}

func TestDeleteStream(t *testing.T) {
	// Given.
	ctx := setUp(t)
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	// When.
	err := deleteStream(ctx, stream.ID)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify stream is deleted.
	_, err = ctx.SSFEventStream(stream.ID)
	if err == nil {
		t.Error("stream should be deleted")
	}
}

func TestDeleteStream_NotFound(t *testing.T) {
	ctx := setUp(t)

	err := deleteStream(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent stream")
	}
}

func TestAddSubject(t *testing.T) {
	// Given.
	ctx := setUp(t)
	ctx.SSFEventStreamSubjectManager = NewEventManager(100)
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	req := requestSubject{
		StreamID: stream.ID,
		Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
	}

	// When.
	err := addSubject(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAddSubject_WithVerified(t *testing.T) {
	// Given.
	ctx := setUp(t)
	ctx.SSFEventStreamSubjectManager = NewEventManager(100)
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	verified := false
	req := requestSubject{
		StreamID: stream.ID,
		Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
		Verified: &verified,
	}

	// When.
	err := addSubject(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAddSubject_InvalidSubject(t *testing.T) {
	// Given.
	ctx := setUp(t)
	ctx.SSFEventStreamSubjectManager = NewEventManager(100)
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	req := requestSubject{
		StreamID: stream.ID,
		Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail}, // missing email
	}

	// When.
	err := addSubject(ctx, req)

	// Then.
	if err == nil {
		t.Error("expected error for invalid subject")
	}
}

func TestRemoveSubject(t *testing.T) {
	// Given.
	ctx := setUp(t)
	manager := NewEventManager(100)
	ctx.SSFEventStreamSubjectManager = manager
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	subject := goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"}
	_ = addSubject(ctx, requestSubject{StreamID: stream.ID, Subject: subject})

	// When.
	err := removeSubject(ctx, requestSubject{StreamID: stream.ID, Subject: subject})

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRemoveSubject_InvalidSubject(t *testing.T) {
	// Given.
	ctx := setUp(t)
	ctx.SSFEventStreamSubjectManager = NewEventManager(100)
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	req := requestSubject{
		StreamID: stream.ID,
		Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail}, // missing email
	}

	// When.
	err := removeSubject(ctx, req)

	// Then.
	if err == nil {
		t.Error("expected error for invalid subject")
	}
}

func TestFetchStreamStatus(t *testing.T) {
	// Given.
	ctx := setUp(t)
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	// When.
	status, err := fetchStreamStatus(ctx, stream.ID)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.ID != stream.ID {
		t.Errorf("stream ID = %s, want %s", status.ID, stream.ID)
	}
	if status.Status != goidc.SSFEventStreamStatusEnabled {
		t.Errorf("status = %s, want %s", status.Status, goidc.SSFEventStreamStatusEnabled)
	}
}

func TestUpdateStreamStatus(t *testing.T) {
	// Given.
	ctx := setUp(t)
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	req := requestStatus{
		ID:           stream.ID,
		Status:       goidc.SSFEventStreamStatusPaused,
		StatusReason: "Maintenance",
	}

	// When.
	status, err := updateStreamStatus(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Status != goidc.SSFEventStreamStatusPaused {
		t.Errorf("status = %s, want %s", status.Status, goidc.SSFEventStreamStatusPaused)
	}
	if status.StatusReason != "Maintenance" {
		t.Errorf("status reason = %s, want Maintenance", status.StatusReason)
	}
}

func TestScheduleVerificationEvent(t *testing.T) {
	// Given.
	ctx := setUp(t)
	manager := NewEventManager(100)
	ctx.SSFEventStreamVerificationManager = manager
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	req := requestVerificationEvent{
		StreamID: stream.ID,
		State:    "test_state",
	}

	// When.
	err := scheduleVerificationEvent(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestScheduleVerificationEvent_RateLimited(t *testing.T) {
	// Given.
	ctx := setUp(t)
	ctx.SSFMinVerificationInterval = 60 // 60 seconds
	manager := NewEventManager(100)
	ctx.SSFEventStreamVerificationManager = manager
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	req := requestVerificationEvent{
		StreamID: stream.ID,
	}

	// First request should succeed.
	if err := scheduleVerificationEvent(ctx, req); err != nil {
		t.Fatalf("first request failed: %v", err)
	}

	// When - second request within interval.
	err := scheduleVerificationEvent(ctx, req)

	// Then.
	if err == nil {
		t.Error("expected rate limit error")
	}
}

func TestScheduleVerificationEvent_NotFound(t *testing.T) {
	ctx := setUp(t)
	ctx.SSFEventStreamVerificationManager = NewEventManager(100)

	err := scheduleVerificationEvent(ctx, requestVerificationEvent{StreamID: "nonexistent"})
	if err == nil {
		t.Error("expected error for nonexistent stream")
	}
}

func TestPublishEvent_PollDelivery(t *testing.T) {
	// Given.
	ctx := setUp(t)
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	event := goidc.SSFEvent{
		Type:    goidc.SSFEventTypeCAEPSessionRevoked,
		Subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
	}

	// When.
	err := PublishEvent(ctx, stream.ID, event)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify event was saved.
	events, _ := ctx.SSFPollEvents(stream.ID, goidc.SSFPollOptions{})
	if len(events.Events) != 1 {
		t.Errorf("got %d events, want 1", len(events.Events))
	}
}

func TestPublishEvent_GeneratesJTI(t *testing.T) {
	// Given.
	ctx := setUp(t)
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	event := goidc.SSFEvent{
		JWTID:   "", // No JTI provided.
		Type:    goidc.SSFEventTypeCAEPSessionRevoked,
		Subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
	}

	// When.
	err := PublishEvent(ctx, stream.ID, event)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	events, _ := ctx.SSFPollEvents(stream.ID, goidc.SSFPollOptions{})
	if len(events.Events) == 0 {
		t.Fatal("expected at least one event")
	}
	if events.Events[0].JWTID == "" {
		t.Error("expected JTI to be generated")
	}
}

func TestPublishEvent_StreamNotSubscribed(t *testing.T) {
	// Given.
	ctx := setUp(t)
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	// Event type not in stream's delivered events (stream only subscribes to CAEPSessionRevoked).
	event := goidc.SSFEvent{
		Type:    goidc.SSFEventTypeStreamUpdated, // Not subscribed to this type.
		Subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
	}

	// When.
	err := PublishEvent(ctx, stream.ID, event)

	// Then.
	if err == nil {
		t.Error("expected error for unsubscribed event type")
	}
}

func TestPublishEvent_StreamDisabled(t *testing.T) {
	// Given.
	ctx := setUp(t)
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	// Disable the stream.
	_, _ = updateStreamStatus(ctx, requestStatus{ID: stream.ID, Status: goidc.SSFEventStreamStatusDisabled})

	event := goidc.SSFEvent{
		Type:    goidc.SSFEventTypeCAEPSessionRevoked,
		Subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
	}

	// When.
	err := PublishEvent(ctx, stream.ID, event)

	// Then - no error, but event is not saved.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	events, _ := ctx.SSFPollEvents(stream.ID, goidc.SSFPollOptions{})
	if len(events.Events) != 0 {
		t.Error("no events should be saved for disabled stream")
	}
}

func TestPublishEvent_VerificationBypassesSubscription(t *testing.T) {
	// Given.
	ctx := setUp(t)
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	// Verification event should work even if not subscribed.
	event := goidc.SSFEvent{
		Type:    goidc.SSFEventTypeVerification,
		Subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
	}

	// When.
	err := PublishEvent(ctx, stream.ID, event)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPublishEvent_StreamNotFound(t *testing.T) {
	ctx := setUp(t)

	err := PublishEvent(ctx, "nonexistent", goidc.SSFEvent{Type: goidc.SSFEventTypeCAEPSessionRevoked})
	if err == nil {
		t.Error("expected error for nonexistent stream")
	}
}

func TestCreateStream_MultipleStreamsNotAllowed(t *testing.T) {
	// Given.
	ctx := setUp(t)
	ctx.SSFMultipleStreamsPerReceiverIsEnabled = false
	_ = createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	// When - try to create a second stream.
	req := request{
		EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
		Delivery:        requestDelivery{Method: goidc.SSFDeliveryMethodPoll},
	}
	_, err := createStream(ctx, req)

	// Then.
	if err == nil {
		t.Error("expected error for multiple streams")
	}
}

func TestCreateStream_WithDescription(t *testing.T) {
	// Given.
	ctx := setUp(t)
	description := "My stream description"
	req := request{
		EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
		Delivery:        requestDelivery{Method: goidc.SSFDeliveryMethodPoll},
		Description:     &description,
	}

	// When.
	resp, err := createStream(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Description != description {
		t.Errorf("description = %s, want %s", resp.Description, description)
	}
}

func TestCreateStream_WithAuthorizationHeader(t *testing.T) {
	// Given.
	ctx := setUp(t)
	endpoint := "https://receiver.com/events"
	authHeader := "Bearer token123"
	req := request{
		EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
		Delivery: requestDelivery{
			Method:              goidc.SSFDeliveryMethodPush,
			Endpoint:            &endpoint,
			AuthorizationHeader: &authHeader,
		},
	}

	// When.
	resp, err := createStream(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ID == "" {
		t.Error("stream ID should not be empty")
	}
}

func TestValidateStream_PollWithAuthHeader(t *testing.T) {
	// Given.
	ctx := setUp(t)
	endpoint := "https://receiver.com/events"
	authHeader := "Bearer token123"
	req := request{
		EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
		Delivery: requestDelivery{
			Method:              goidc.SSFDeliveryMethodPoll,
			Endpoint:            &endpoint,
			AuthorizationHeader: &authHeader,
		},
	}

	// When.
	_, err := createStream(ctx, req)

	// Then.
	if err == nil {
		t.Error("expected error for poll with endpoint")
	}
}

func TestNewConfiguration(t *testing.T) {
	// Given.
	ctx := setUp(t)
	ctx.SSFIsStatusManagementEnabled = true
	ctx.SSFIsSubjectManagementEnabled = true
	ctx.SSFStatusEndpoint = "/ssf/status"
	ctx.SSFAddSubjectEndpoint = "/ssf/subjects/add"
	ctx.SSFRemoveSubjectEndpoint = "/ssf/subjects/remove"
	ctx.SSFVerificationEndpoint = "/ssf/verification"
	ctx.SSFCriticalSubjectMembers = []string{"user", "tenant"}
	ctx.SSFAuthorizationSchemes = []goidc.SSFAuthorizationScheme{{SpecificationURN: "bearer"}}
	ctx.SSFDefaultSubjects = goidc.SSFDefaultSubjectAll

	// When.
	config := newConfiguration(ctx)

	// Then.
	if config.Issuer != ctx.Issuer() {
		t.Errorf("issuer = %s, want %s", config.Issuer, ctx.Issuer())
	}
	if config.SpecVersion != specVersion {
		t.Errorf("spec_version = %s, want %s", config.SpecVersion, specVersion)
	}
	if config.StatusEndpoint == "" {
		t.Error("status_endpoint should be set")
	}
	if config.AddSubjectEndpoint == "" {
		t.Error("add_subject_endpoint should be set")
	}
	if config.RemoveSubjectEndpoint == "" {
		t.Error("remove_subject_endpoint should be set")
	}
	if config.VerificationEndpoint == "" {
		t.Error("verification_endpoint should be set")
	}
}

func TestNewConfiguration_Minimal(t *testing.T) {
	// Given.
	ctx := setUp(t)
	ctx.SSFIsStatusManagementEnabled = false
	ctx.SSFIsSubjectManagementEnabled = false
	ctx.SSFIsVerificationEnabled = false

	// When.
	config := newConfiguration(ctx)

	// Then.
	if config.StatusEndpoint != "" {
		t.Error("status_endpoint should be empty")
	}
	if config.AddSubjectEndpoint != "" {
		t.Error("add_subject_endpoint should be empty")
	}
	if config.VerificationEndpoint != "" {
		t.Error("verification_endpoint should be empty")
	}
}

func TestPollEvents_WithErrors(t *testing.T) {
	// Given.
	ctx := setUp(t)
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	// Save events.
	for i := range 3 {
		event := goidc.SSFEvent{
			JWTID:   fmt.Sprintf("jti_%d", i),
			Type:    goidc.SSFEventTypeCAEPSessionRevoked,
			Subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
		}
		if err := ctx.SSFSaveEvent(stream.ID, event); err != nil {
			t.Fatalf("error saving event: %v", err)
		}
	}

	// When - poll with error acknowledgement.
	_, err := pollEvents(ctx, stream.ID, requestPollEvents{
		Errors: map[string]goidc.SSFEventError{
			"jti_0": {Error: goidc.SSFEventErrorCodeInvalidRequest, Description: "bad event"},
		},
	})

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Poll again to verify event was removed.
	resp, _ := pollEvents(ctx, stream.ID, requestPollEvents{})
	if len(resp.SecurityEventTokens) != 2 {
		t.Errorf("got %d events after error ack, want 2", len(resp.SecurityEventTokens))
	}
}

func TestCompareSubjects_EdgeCases(t *testing.T) {
	testCases := []struct {
		name  string
		a, b  *goidc.SSFSubject
		match bool
	}{
		{
			name:  "both nil",
			a:     nil,
			b:     nil,
			match: true,
		},
		{
			name:  "first nil",
			a:     nil,
			b:     &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
			match: true,
		},
		{
			name:  "second nil",
			a:     &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
			b:     nil,
			match: true,
		},
		{
			name: "complex with different tenant",
			a: &goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				Tenant: &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "tenant1"},
			},
			b: &goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				Tenant: &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "tenant2"},
			},
			match: false,
		},
		{
			name: "complex with different device",
			a: &goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				Device: &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "device1"},
			},
			b: &goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				Device: &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "device2"},
			},
			match: false,
		},
		{
			name: "complex with different org_unit",
			a: &goidc.SSFSubject{
				Format:             goidc.SSFSubjectFormatComplex,
				OrganizationalUnit: &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "org1"},
			},
			b: &goidc.SSFSubject{
				Format:             goidc.SSFSubjectFormatComplex,
				OrganizationalUnit: &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "org2"},
			},
			match: false,
		},
		{
			name: "complex with different application",
			a: &goidc.SSFSubject{
				Format:      goidc.SSFSubjectFormatComplex,
				Application: &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "app1"},
			},
			b: &goidc.SSFSubject{
				Format:      goidc.SSFSubjectFormatComplex,
				Application: &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "app2"},
			},
			match: false,
		},
		{
			name: "complex with different group",
			a: &goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				Group:  &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "group1"},
			},
			b: &goidc.SSFSubject{
				Format: goidc.SSFSubjectFormatComplex,
				Group:  &goidc.SSFSubject{Format: goidc.SSFSubjectFormatOpaque, ID: "group2"},
			},
			match: false,
		},
		{
			name: "complex with different additional properties",
			a: &goidc.SSFSubject{
				Format:               goidc.SSFSubjectFormatComplex,
				User:                 &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				AdditionalProperties: map[string]goidc.SSFSubject{"key": {Format: goidc.SSFSubjectFormatOpaque, ID: "val1"}},
			},
			b: &goidc.SSFSubject{
				Format:               goidc.SSFSubjectFormatComplex,
				User:                 &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				AdditionalProperties: map[string]goidc.SSFSubject{"key": {Format: goidc.SSFSubjectFormatOpaque, ID: "val2"}},
			},
			match: false,
		},
		{
			name: "complex with additional properties key not in both",
			a: &goidc.SSFSubject{
				Format:               goidc.SSFSubjectFormatComplex,
				User:                 &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				AdditionalProperties: map[string]goidc.SSFSubject{"key1": {Format: goidc.SSFSubjectFormatOpaque, ID: "val1"}},
			},
			b: &goidc.SSFSubject{
				Format:               goidc.SSFSubjectFormatComplex,
				User:                 &goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
				AdditionalProperties: map[string]goidc.SSFSubject{"key2": {Format: goidc.SSFSubjectFormatOpaque, ID: "val2"}},
			},
			match: true, // key not in both, so match
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := compareSubjects(tc.a, tc.b)
			if result != tc.match {
				t.Errorf("compareSubjects() = %v, want %v", result, tc.match)
			}
		})
	}
}

func TestToResponse_WithInactivityTimeout(t *testing.T) {
	// Given.
	ctx := setUp(t)
	ctx.SSFInactivityTimeoutSecs = 3600

	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	// Fetch the stream to update the expiration.
	_, _ = fetchStream(ctx, stream.ID)

	// Fetch again to get the response with inactivity timeout.
	resp, err := fetchStream(ctx, stream.ID)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// InactivityTimeout should be set (close to 3600).
	if resp.InactivityTimeout <= 0 || resp.InactivityTimeout > 3600 {
		t.Errorf("inactivity_timeout = %d, want > 0 and <= 3600", resp.InactivityTimeout)
	}
}

func TestReceiverAndStream_WrongOwner(t *testing.T) {
	// Given.
	ctx := setUp(t)
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	// Change authenticated receiver to a different one.
	ctx.SSFAuthenticatedReceiverFunc = func(_ context.Context) (goidc.SSFReceiver, error) {
		return goidc.SSFReceiver{
			ID: "different_receiver",
		}, nil
	}

	// When.
	_, err := fetchStream(ctx, stream.ID)

	// Then.
	if err == nil {
		t.Error("expected access denied error for wrong owner")
	}
}

func TestIntersection(t *testing.T) {
	testCases := []struct {
		name string
		a, b []goidc.SSFEventType
		want []goidc.SSFEventType
	}{
		{
			name: "overlapping events",
			a:    []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked, goidc.SSFEventTypeCAEPCredentialChange},
			b:    []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked, goidc.SSFEventTypeVerification},
			want: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
		},
		{
			name: "no overlap",
			a:    []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
			b:    []goidc.SSFEventType{goidc.SSFEventTypeCAEPCredentialChange},
			want: []goidc.SSFEventType{},
		},
		{
			name: "empty input",
			a:    []goidc.SSFEventType{},
			b:    []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
			want: []goidc.SSFEventType{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := intersection(tc.a, tc.b)
			if diff := cmp.Diff(got, tc.want, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("intersection() diff: %s", diff)
			}
		})
	}
}

func TestPatchStream_ChangeDeliveryMethod(t *testing.T) {
	// Given.
	ctx := setUp(t)
	endpoint := "https://receiver.com/events"
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	// When - change delivery method and add endpoint.
	patchReq := request{
		ID: stream.ID,
		Delivery: requestDelivery{
			Method:   goidc.SSFDeliveryMethodPush,
			Endpoint: &endpoint,
		},
	}
	resp, err := patchStream(ctx, patchReq)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Delivery.Method != goidc.SSFDeliveryMethodPush {
		t.Errorf("delivery method = %s, want %s", resp.Delivery.Method, goidc.SSFDeliveryMethodPush)
	}
}

func TestPatchStream_ChangeAuthorizationHeader(t *testing.T) {
	// Given.
	ctx := setUp(t)
	endpoint := "https://receiver.com/events"
	authHeader := "Bearer initial"
	createReq := request{
		EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
		Delivery: requestDelivery{
			Method:              goidc.SSFDeliveryMethodPush,
			Endpoint:            &endpoint,
			AuthorizationHeader: &authHeader,
		},
	}
	resp, _ := createStream(ctx, createReq)

	// When - change authorization header.
	newAuthHeader := "Bearer updated"
	patchReq := request{
		ID: resp.ID,
		Delivery: requestDelivery{
			AuthorizationHeader: &newAuthHeader,
		},
	}
	_, err := patchStream(ctx, patchReq)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReceiverAndStream_ExpiredStream(t *testing.T) {
	// Given.
	ctx := setUp(t)
	ctx.SSFInactivityTimeoutSecs = 1 // Very short timeout for testing.
	handlerCalled := false
	ctx.SSFHandleExpiredEventStreamFunc = func(_ context.Context, _ *goidc.SSFEventStream) error {
		handlerCalled = true
		return nil
	}
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	// Manually expire the stream by setting a past timestamp.
	s, _ := ctx.SSFEventStream(stream.ID)
	s.ExpiresAtTimestamp = 1 // Epoch + 1 second (definitely expired).
	_ = ctx.SSFUpdateEventStream(s)

	// When - access the stream.
	_, err := fetchStream(ctx, stream.ID)

	// Then - stream should be accessible and handler should be called.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !handlerCalled {
		t.Error("expired stream handler should be called")
	}
}

func TestFetchStreams_Empty(t *testing.T) {
	// Given.
	ctx := setUp(t)
	// Don't create any streams.

	// When.
	streams, err := fetchStreams(ctx)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(streams) != 0 {
		t.Errorf("got %d streams, want 0", len(streams))
	}
}

func TestAddSubject_StreamNotFound(t *testing.T) {
	// Given.
	ctx := setUp(t)
	ctx.SSFEventStreamSubjectManager = NewEventManager(100)

	req := requestSubject{
		StreamID: "nonexistent",
		Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
	}

	// When.
	err := addSubject(ctx, req)

	// Then.
	if err == nil {
		t.Error("expected error for nonexistent stream")
	}
}

func TestRemoveSubject_StreamNotFound(t *testing.T) {
	// Given.
	ctx := setUp(t)
	ctx.SSFEventStreamSubjectManager = NewEventManager(100)

	req := requestSubject{
		StreamID: "nonexistent",
		Subject:  goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
	}

	// When.
	err := removeSubject(ctx, req)

	// Then.
	if err == nil {
		t.Error("expected error for nonexistent stream")
	}
}

func TestFetchStreamStatus_StreamNotFound(t *testing.T) {
	ctx := setUp(t)

	_, err := fetchStreamStatus(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent stream")
	}
}

func TestUpdateStreamStatus_StreamNotFound(t *testing.T) {
	ctx := setUp(t)

	_, err := updateStreamStatus(ctx, requestStatus{ID: "nonexistent", Status: goidc.SSFEventStreamStatusPaused})
	if err == nil {
		t.Error("expected error for nonexistent stream")
	}
}

func TestPublishEvent_UnsupportedDeliveryMethod(t *testing.T) {
	// Given.
	ctx := setUp(t)
	stream := createTestStream(t, ctx, goidc.SSFDeliveryMethodPoll)

	// Manually change the delivery method to an unsupported one.
	s, _ := ctx.SSFEventStream(stream.ID)
	s.DeliveryMethod = "unsupported"
	_ = ctx.SSFUpdateEventStream(s)

	event := goidc.SSFEvent{
		Type:    goidc.SSFEventTypeCAEPSessionRevoked,
		Subject: goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"},
	}

	// When.
	err := PublishEvent(ctx, stream.ID, event)

	// Then.
	if err == nil {
		t.Error("expected error for unsupported delivery method")
	}
}

func TestReceiverWithCustomAudiences(t *testing.T) {
	// Given.
	ctx := setUp(t)
	ctx.SSFAuthenticatedReceiverFunc = func(_ context.Context) (goidc.SSFReceiver, error) {
		return goidc.SSFReceiver{
			ID:        testReceiverID,
			Audiences: []string{"custom_aud_1", "custom_aud_2"},
		}, nil
	}

	req := request{
		EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
		Delivery:        requestDelivery{Method: goidc.SSFDeliveryMethodPoll},
	}

	// When.
	resp, err := createStream(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Audience) != 2 || resp.Audience[0] != "custom_aud_1" {
		t.Errorf("audience = %v, want [custom_aud_1, custom_aud_2]", resp.Audience)
	}
}

func setUp(t *testing.T) oidc.Context {
	t.Helper()

	ctx := oidctest.NewContext(t)
	manager := NewEventManager(100)
	ctx.SSFAuthenticatedReceiverFunc = func(_ context.Context) (goidc.SSFReceiver, error) {
		return goidc.SSFReceiver{
			ID: testReceiverID,
		}, nil
	}
	ctx.SSFEventStreamManager = manager
	ctx.SSFEventPollManager = manager
	ctx.SSFDeliveryMethods = []goidc.SSFDeliveryMethod{goidc.SSFDeliveryMethodPush, goidc.SSFDeliveryMethodPoll}
	ctx.SSFEventsSupported = []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked, goidc.SSFEventTypeCAEPCredentialChange}
	ctx.SSFIsVerificationEnabled = true
	ctx.SSFSignatureAlgorithm = goidc.PS256
	ctx.SSFJWKSFunc = ctx.JWKSFunc
	ctx.SSFPollingEndpoint = "/ssf/poll"

	return ctx
}

func createTestStream(t *testing.T, ctx oidc.Context, method goidc.SSFDeliveryMethod) *goidc.SSFEventStream {
	t.Helper()

	var endpoint *string
	if method == goidc.SSFDeliveryMethodPush {
		e := "https://receiver.com/events"
		endpoint = &e
	}

	req := request{
		EventsRequested: []goidc.SSFEventType{goidc.SSFEventTypeCAEPSessionRevoked},
		Delivery: requestDelivery{
			Method:   method,
			Endpoint: endpoint,
		},
	}

	resp, err := createStream(ctx, req)
	if err != nil {
		t.Fatalf("failed to create test stream: %v", err)
	}

	stream, err := ctx.SSFEventStream(resp.ID)
	if err != nil {
		t.Fatalf("failed to fetch created stream: %v", err)
	}

	return stream
}
