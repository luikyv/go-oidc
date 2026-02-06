package ssf

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type EventManager struct {
	streams map[string]*goidc.SSFEventStream
	// streamSubjects is a map of stream ids to subjects.
	streamSubjects map[string][]goidc.SSFSubject
	// streamPollEvents is a map of stream ids to pending poll events.
	streamPollEvents map[string][]goidc.SSFEvent
	// maxPollEvents is the maximum number of events to poll.
	maxPollEvents int
	maxStreams    int
	lock          sync.RWMutex
}

func NewEventManager(maxStreams int) *EventManager {
	return &EventManager{
		streams:          make(map[string]*goidc.SSFEventStream),
		streamSubjects:   make(map[string][]goidc.SSFSubject),
		streamPollEvents: make(map[string][]goidc.SSFEvent),
		maxPollEvents:    3,
		maxStreams:       maxStreams,
	}
}

func (m *EventManager) Create(_ context.Context, stream *goidc.SSFEventStream) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if len(m.streams) >= m.maxStreams {
		removeOldest(m.streams, func(s *goidc.SSFEventStream) int {
			return s.CreatedAtTimestamp
		})
	}

	m.streams[stream.ID] = stream
	return nil
}

func (m *EventManager) Update(_ context.Context, stream *goidc.SSFEventStream) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.streams[stream.ID] = stream
	return nil
}

func (m *EventManager) EventStream(_ context.Context, id string) (*goidc.SSFEventStream, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	if stream, ok := m.streams[id]; ok {
		return stream, nil
	}
	return nil, errors.New("stream not found")
}

func (m *EventManager) EventStreams(_ context.Context, receiverID string) ([]*goidc.SSFEventStream, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	var streams []*goidc.SSFEventStream
	for _, stream := range m.streams {
		if stream.ReceiverID == receiverID {
			streams = append(streams, stream)
		}
	}
	return streams, nil
}

func (m *EventManager) Delete(_ context.Context, id string) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.streams, id)
	delete(m.streamSubjects, id)
	delete(m.streamPollEvents, id)
	return nil
}

func (m *EventManager) Add(_ context.Context, streamID string, sub goidc.SSFSubject, _ goidc.SSFSubjectOptions) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	subjects := m.streamSubjects[streamID]
	if !slices.ContainsFunc(subjects, func(s goidc.SSFSubject) bool {
		return compareSubjects(&s, &sub)
	}) {
		m.streamSubjects[streamID] = append(subjects, sub)
	}
	return nil
}

func (m *EventManager) Remove(_ context.Context, streamID string, sub goidc.SSFSubject) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.streamSubjects[streamID] = slices.DeleteFunc(m.streamSubjects[streamID], func(s goidc.SSFSubject) bool {
		return compareSubjects(&s, &sub)
	})
	return nil
}

func (m *EventManager) Save(_ context.Context, streamID string, event goidc.SSFEvent) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.streamPollEvents[streamID] = append(m.streamPollEvents[streamID], event)
	return nil
}

func (m *EventManager) Poll(_ context.Context, streamID string, opts goidc.SSFPollOptions) (goidc.SSFEvents, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	events := m.streamPollEvents[streamID]
	if len(events) == 0 {
		return goidc.SSFEvents{}, nil
	}

	maxEvents := m.maxPollEvents
	if opts.MaxEvents != nil && *opts.MaxEvents < maxEvents {
		maxEvents = *opts.MaxEvents
	}

	moreAvailable := len(events) > maxEvents
	if moreAvailable {
		events = events[:maxEvents]
	}

	return goidc.SSFEvents{Events: events, MoreAvailable: moreAvailable}, nil
}

func (m *EventManager) Acknowledge(_ context.Context, streamID string, jtis []string, _ goidc.SSFAcknowledgementOptions) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.streamPollEvents[streamID] = slices.DeleteFunc(m.streamPollEvents[streamID], func(e goidc.SSFEvent) bool {
		return slices.Contains(jtis, e.JWTID)
	})
	return nil
}

func (m *EventManager) AcknowledgeErrors(_ context.Context, streamID string, errs map[string]goidc.SSFEventError, _ goidc.SSFAcknowledgementOptions) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.streamPollEvents[streamID] = slices.DeleteFunc(m.streamPollEvents[streamID], func(e goidc.SSFEvent) bool {
		_, hasError := errs[e.JWTID]
		return hasError
	})
	return nil
}

func (m *EventManager) Schedule(ctx context.Context, streamID string, opts goidc.SSFStreamVerificationOptions) error {
	oidcCtx, ok := ctx.(oidc.Context)
	if !ok {
		return nil
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_ = PublishEvent(oidc.NewContext(ctx, oidcCtx.Configuration), streamID, goidc.NewSSFVerificationEvent(streamID, opts))
	}()
	return nil
}

func removeOldest[T any](m map[string]T, createdAtFunc func(T) int) {
	var oldestKey string
	var oldestCreatedAt int

	for key, value := range m {
		createdAt := createdAtFunc(value)
		if oldestCreatedAt == 0 || createdAt < oldestCreatedAt {
			oldestKey = key
			oldestCreatedAt = createdAt
		}
	}

	delete(m, oldestKey)
}
