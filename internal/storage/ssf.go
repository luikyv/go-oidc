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

// SSFPushEvent is set by the SSF package to deliver verification events for
// push-based streams without making storage import the SSF package.
var SSFPushEvent func(oidc.Context, string, goidc.SSFEvent) error

// SSFCompareSubjects is set by the SSF package to compare subjects using SSF
// subject matching rules without making storage import the SSF package.
var SSFCompareSubjects func(oidc.Context, goidc.SSFSubject, goidc.SSFSubject) error

func (m *Manager) SaveStream(_ context.Context, stream *goidc.SSFStream) error {
	m.streamMutex.Lock()
	defer m.streamMutex.Unlock()

	if len(m.SSFStreams) >= m.maxSize {
		removeOldest(m.SSFStreams, func(s *goidc.SSFStream) int {
			return s.CreatedAt
		})
	}

	m.SSFStreams[stream.ID] = stream
	return nil
}

func (m *Manager) Stream(_ context.Context, id string) (*goidc.SSFStream, error) {
	m.streamMutex.RLock()
	defer m.streamMutex.RUnlock()
	if stream, ok := m.SSFStreams[id]; ok {
		streamCopy := *stream
		return &streamCopy, nil
	}
	return nil, goidc.ErrNotFound
}

func (m *Manager) Streams(_ context.Context, receiverID string) ([]*goidc.SSFStream, error) {
	m.streamMutex.RLock()
	defer m.streamMutex.RUnlock()
	var streams []*goidc.SSFStream
	for _, stream := range m.SSFStreams {
		if stream.ReceiverID == receiverID {
			streamCopy := *stream
			streams = append(streams, &streamCopy)
		}
	}
	return streams, nil
}

func (m *Manager) DeleteStream(_ context.Context, id string) error {
	m.streamMutex.Lock()
	defer m.streamMutex.Unlock()
	delete(m.SSFStreams, id)
	delete(m.streamSubjects, id)
	delete(m.streamPollEvents, id)
	return nil
}

func (m *Manager) AddStreamSubject(ctx context.Context, streamID string, sub goidc.SSFSubject, _ goidc.SSFSubjectOptions) error {
	m.streamMutex.Lock()
	defer m.streamMutex.Unlock()

	subjects := m.streamSubjects[streamID]
	if !slices.ContainsFunc(subjects, func(s goidc.SSFSubject) bool {
		return subjectsMatch(ctx, s, sub)
	}) {
		m.streamSubjects[streamID] = append(subjects, sub)
	}
	return nil
}

func (m *Manager) RemoveStreamSubject(ctx context.Context, streamID string, sub goidc.SSFSubject) error {
	m.streamMutex.Lock()
	defer m.streamMutex.Unlock()
	m.streamSubjects[streamID] = slices.DeleteFunc(m.streamSubjects[streamID], func(s goidc.SSFSubject) bool {
		return subjectsMatch(ctx, s, sub)
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

func (m *Manager) ScheduleVerificationEvent(ctx context.Context, streamID string, event goidc.SSFEvent) error {
	oidcCtx, ok := ctx.(oidc.Context)
	if !ok {
		return nil
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		oidcCtx = oidc.NewContext(ctx, oidcCtx.Configuration)

		stream, err := m.Stream(ctx, streamID)
		if err != nil {
			log.Printf("could not fetch stream %s\n", streamID)
			return
		}

		if stream.Delivery.Method == goidc.SSFDeliveryMethodPoll {
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

func subjectsMatch(ctx context.Context, a, b goidc.SSFSubject) bool {
	if oidcCtx, ok := ctx.(oidc.Context); ok && SSFCompareSubjects != nil {
		return SSFCompareSubjects(oidcCtx, a, b) == nil
	}

	return compareSSFSubjects(&a, &b)
}

func compareSSFSubjects(a, b *goidc.SSFSubject) bool {
	if a == nil || b == nil {
		return true
	}

	if a.Format != b.Format {
		return false
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

	for key, valueA := range a.AdditionalMembers {
		valueB, ok := b.AdditionalMembers[key]
		if ok && !compareSSFSubjects(&valueA, &valueB) {
			return false
		}
	}
	return true
}
