package ssf

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	testReceiverID = "test_receiver_id"
)

func TestCreateStream(t *testing.T) {
	// Given.
	ctx := setUp(t)
	req := request{
		EventsRequested: []goidc.SSFEventType{
			goidc.SSFEventTypeVerification,
		},
		Delivery: delivery{
			Method: goidc.SSFDeliveryMethodPush,
		},
		Description: "test description",
	}

	// When.
	stream, err := createStream(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error creating the stream: %v", err)
	}

	if diff := cmp.Diff(stream, &goidc.SSFEventStream{
		ID:         stream.ID,
		ReceiverID: testReceiverID,
	}); diff != "" {
		t.Error(diff)
	}
}

func setUp(t *testing.T) oidc.Context {
	t.Helper()

	ctx := oidctest.NewContext(t)
	ctx.SSFAuthenticatedReceiverFunc = func(r *http.Request) (goidc.SSFReceiver, error) {
		return goidc.SSFReceiver{
			ID: testReceiverID,
		}, nil
	}
	// ctx.SSFEventStreamManager = storage.NewSSFEventStreamManager(100)

	return ctx
}
