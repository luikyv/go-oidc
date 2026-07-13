package ssf

import (
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/storage"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func init() {
	storage.SSFPushEvent = PushEvent
	storage.SSFCompareSubjects = CompareSubjects
}

// authorizedStream returns the stream when it exists and belongs to the
// authenticated receiver.
func authorizedStream(ctx oidc.Context, id string) (*goidc.SSFStream, goidc.SSFReceiver, error) {
	r, err := receiver(ctx)
	if err != nil {
		return nil, goidc.SSFReceiver{}, fmt.Errorf("could not load the authenticated receiver: %w", err)
	}

	if id == "" {
		return nil, goidc.SSFReceiver{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "stream_id is required")
	}

	stream, err := ctx.SSFStream(id)
	if err != nil {
		if errors.Is(err, goidc.ErrNotFound) {
			return nil, goidc.SSFReceiver{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "stream was not found").WithStatusCode(http.StatusNotFound)
		}
		return nil, goidc.SSFReceiver{}, fmt.Errorf("could not load the event stream %q: %w", id, err)
	}

	if stream.ReceiverID != r.ID {
		return nil, goidc.SSFReceiver{}, goidc.WrapError(goidc.ErrorCodeAccessDenied, "access denied", errors.New("stream not owned by receiver"))
	}

	return stream, r, nil
}

func receiver(ctx oidc.Context) (goidc.SSFReceiver, error) {
	r, err := ctx.SSFReceiver()
	if err != nil {
		return goidc.SSFReceiver{}, fmt.Errorf("could not load the receiver: %w", err)
	}
	r.EventTypes = func() []goidc.SSFEventType {
		if r.EventTypes == nil {
			return ctx.SSFEventTypes
		}

		// Make sure event types supplied for the receiver are supported.
		eventTypes := make([]goidc.SSFEventType, 0)
		for _, e := range r.EventTypes {
			if slices.Contains(ctx.SSFEventTypes, e) {
				eventTypes = append(eventTypes, e)
			}
		}
		return eventTypes
	}()

	return r, nil
}
