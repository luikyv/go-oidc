package storage

import (
	"context"
	"log"
	"reflect"
	"slices"
	"time"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type SSFPushEventFunc func(oidc.Context, string, goidc.SSFEvent) error

// SSFPushEvent is set by the SSF package to deliver verification events for
// push-based streams without making storage import the SSF package.
var SSFPushEvent SSFPushEventFunc

func (m *Manager) CreateEventStream(_ context.Context, stream *goidc.SSFEventStream) error {
	m.streamMutex.Lock()
	defer m.streamMutex.Unlock()

	if len(m.Streams) >= m.maxSize {
		removeOldest(m.Streams, func(s *goidc.SSFEventStream) int {
			return s.CreatedAt
		})
	}

	m.Streams[stream.ID] = stream
	return nil
}

func (m *Manager) UpdateEventStream(_ context.Context, stream *goidc.SSFEventStream) error {
	m.streamMutex.Lock()
	defer m.streamMutex.Unlock()
	m.Streams[stream.ID] = stream
	return nil
}

func (m *Manager) EventStream(_ context.Context, id string) (*goidc.SSFEventStream, error) {
	m.streamMutex.RLock()
	defer m.streamMutex.RUnlock()
	if stream, ok := m.Streams[id]; ok {
		return stream, nil
	}
	return nil, goidc.ErrNotFound
}

func (m *Manager) EventStreams(_ context.Context, receiverID string) ([]*goidc.SSFEventStream, error) {
	m.streamMutex.RLock()
	defer m.streamMutex.RUnlock()
	var streams []*goidc.SSFEventStream
	for _, stream := range m.Streams {
		if stream.ReceiverID == receiverID {
			streams = append(streams, stream)
		}
	}
	return streams, nil
}

func (m *Manager) DeleteEventStream(_ context.Context, id string) error {
	m.streamMutex.Lock()
	defer m.streamMutex.Unlock()
	delete(m.Streams, id)
	delete(m.streamSubjects, id)
	delete(m.streamPollEvents, id)
	return nil
}

func (m *Manager) AddStreamSubject(_ context.Context, streamID string, sub goidc.SSFSubject, _ goidc.SSFSubjectOptions) error {
	m.streamMutex.Lock()
	defer m.streamMutex.Unlock()

	subjects := m.streamSubjects[streamID]
	if !slices.ContainsFunc(subjects, func(s goidc.SSFSubject) bool {
		return compareSSFSubjects(&s, &sub)
	}) {
		m.streamSubjects[streamID] = append(subjects, sub)
	}
	return nil
}

func (m *Manager) RemoveStreamSubject(_ context.Context, streamID string, sub goidc.SSFSubject) error {
	m.streamMutex.Lock()
	defer m.streamMutex.Unlock()
	m.streamSubjects[streamID] = slices.DeleteFunc(m.streamSubjects[streamID], func(s goidc.SSFSubject) bool {
		return compareSSFSubjects(&s, &sub)
	})
	return nil
}

func (m *Manager) SaveEvent(_ context.Context, streamID string, event goidc.SSFEvent) error {
	m.streamMutex.Lock()
	defer m.streamMutex.Unlock()
	m.streamPollEvents[streamID] = append(m.streamPollEvents[streamID], event)
	return nil
}

func (m *Manager) PollEvents(_ context.Context, streamID string, opts goidc.SSFPollOptions) (goidc.SSFEvents, error) {
	m.streamMutex.RLock()
	defer m.streamMutex.RUnlock()

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

func (m *Manager) AcknowledgeEvents(_ context.Context, streamID string, ids []string, _ goidc.SSFAcknowledgementOptions) error {
	m.streamMutex.Lock()
	defer m.streamMutex.Unlock()
	m.streamPollEvents[streamID] = slices.DeleteFunc(m.streamPollEvents[streamID], func(e goidc.SSFEvent) bool {
		return slices.Contains(ids, e.ID)
	})
	return nil
}

func (m *Manager) AcknowledgeEventErrors(_ context.Context, streamID string, errs []goidc.SSFEventError, _ goidc.SSFAcknowledgementOptions) error {
	m.streamMutex.Lock()
	defer m.streamMutex.Unlock()
	m.streamPollEvents[streamID] = slices.DeleteFunc(m.streamPollEvents[streamID], func(e goidc.SSFEvent) bool {
		return slices.ContainsFunc(errs, func(err goidc.SSFEventError) bool {
			return err.ID == e.ID
		})
	})
	return nil
}

func (m *Manager) ScheduleVerificationEvent(ctx context.Context, streamID string, opts goidc.SSFStreamVerificationOptions) error {
	go func() {
		oidcCtx := ctx.(oidc.Context)
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		oidcCtx = oidc.NewContext(ctx, oidcCtx.Configuration)

		stream, err := m.EventStream(ctx, streamID)
		if err != nil {
			log.Printf("could not fetch stream %s\n", streamID)
			return
		}

		event := goidc.NewSSFVerificationEvent(oidcCtx.JWTID(), streamID, opts)
		if stream.DeliveryMethod == goidc.SSFDeliveryMethodPoll {
			_ = m.SaveEvent(ctx, streamID, event)
			return
		}

		if SSFPushEvent == nil {
			log.Printf("could not push SSF verification event for stream %s: push function is not configured\n", streamID)
			return
		}
		_ = SSFPushEvent(oidcCtx, streamID, event)
	}()
	return nil
}

func compareSSFSubjects(a, b *goidc.SSFSubject) bool {
	if a == nil || b == nil {
		return true
	}

	if a.Format != goidc.SSFSubjectFormatComplex && b.Format != goidc.SSFSubjectFormatComplex {
		return reflect.DeepEqual(a, b)
	}

	if !compareSSFSubjects(a.User, b.User) {
		return false
	}
	if !compareSSFSubjects(a.Tenant, b.Tenant) {
		return false
	}
	if !compareSSFSubjects(a.Device, b.Device) {
		return false
	}
	if !compareSSFSubjects(a.Session, b.Session) {
		return false
	}
	if !compareSSFSubjects(a.OrganizationalUnit, b.OrganizationalUnit) {
		return false
	}
	if !compareSSFSubjects(a.Application, b.Application) {
		return false
	}
	if !compareSSFSubjects(a.Group, b.Group) {
		return false
	}

	for key, valueA := range a.AdditionalProperties {
		valueB, ok := b.AdditionalProperties[key]
		if ok && !compareSSFSubjects(&valueA, &valueB) {
			return false
		}
	}
	return true
}
