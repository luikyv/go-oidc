package storage

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sync"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type SSFManager struct {
	Streams             map[string]*goidc.SSFEventStream
	StreamSubjects      map[string][]goidc.SSFSubject
	StreamEvents        map[string][]goidc.SSFEvent
	StreamVerifications map[string]goidc.SSFStreamVerificationOptions
	maxSize             int
	maxEvents           int
	mu                  sync.RWMutex
}

func NewSSFManager(maxSize int) *SSFManager {
	return &SSFManager{
		Streams:             make(map[string]*goidc.SSFEventStream),
		StreamSubjects:      make(map[string][]goidc.SSFSubject),
		StreamEvents:        make(map[string][]goidc.SSFEvent),
		StreamVerifications: make(map[string]goidc.SSFStreamVerificationOptions),
		maxSize:             maxSize,
		maxEvents:           3,
	}
}

func (m *SSFManager) Create(ctx context.Context, stream *goidc.SSFEventStream) error {
	return m.save(ctx, stream)
}
func (m *SSFManager) Update(ctx context.Context, stream *goidc.SSFEventStream) error {
	return m.save(ctx, stream)
}

func (m *SSFManager) save(_ context.Context, stream *goidc.SSFEventStream) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.Streams) >= m.maxSize {
		removeOldest(m.Streams, func(s *goidc.SSFEventStream) int {
			return s.CreatedAtTimestamp
		})
	}

	m.Streams[stream.ID] = stream
	if _, exists := m.StreamSubjects[stream.ID]; !exists {
		m.StreamSubjects[stream.ID] = make([]goidc.SSFSubject, 0)
	}
	return nil
}

func (m *SSFManager) EventStream(_ context.Context, id string) (*goidc.SSFEventStream, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stream, exists := m.Streams[id]
	if !exists {
		return nil, errors.New("entity not found")
	}

	return stream, nil
}

func (m *SSFManager) EventStreams(_ context.Context, receiverID string) ([]*goidc.SSFEventStream, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	streams := make([]*goidc.SSFEventStream, 0, len(m.Streams))
	for _, stream := range m.Streams {
		if stream.ReceiverID != receiverID {
			continue
		}
		streams = append(streams, stream)
	}

	return streams, nil
}

func (m *SSFManager) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.Streams, id)
	delete(m.StreamSubjects, id)
	delete(m.StreamEvents, id)
	return nil
}

func (m *SSFManager) Add(_ context.Context, id string, sub goidc.SSFSubject, opts goidc.SSFSubjectOptions) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.StreamSubjects[id] = append(m.StreamSubjects[id], sub)
	return nil
}

func (m *SSFManager) Remove(_ context.Context, streamID string, sub goidc.SSFSubject) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	subjects := make([]goidc.SSFSubject, 0, len(m.StreamSubjects[streamID]))
	for _, s := range m.StreamSubjects[streamID] {
		// Remove all subjects that match the given subject.
		if compareSSFSubjects(&s, &sub) {
			continue
		}
		subjects = append(subjects, s)
	}
	m.StreamSubjects[streamID] = subjects

	return nil
}

func (m *SSFManager) Save(_ context.Context, streamID string, event goidc.SSFEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.StreamEvents[streamID] = append(m.StreamEvents[streamID], event)
	return nil
}

func (m *SSFManager) Poll(_ context.Context, streamID string, opts goidc.SSFPollOptions) (goidc.SSFEvents, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	events := m.StreamEvents[streamID]
	if len(events) == 0 {
		return goidc.SSFEvents{}, nil
	}

	moreAvailable := false
	maxEvents := m.maxEvents
	if opts.MaxEvents != nil && *opts.MaxEvents < maxEvents {
		maxEvents = *opts.MaxEvents
	}
	if len(events) > maxEvents {
		events = events[:maxEvents]
		moreAvailable = true
	}

	return goidc.SSFEvents{
		Events:        events,
		MoreAvailable: moreAvailable,
	}, nil
}

func (m *SSFManager) Acknowledge(_ context.Context, streamID string, jtis []string, opts goidc.SSFAcknowledgementOptions) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	remainingEvents := make([]goidc.SSFEvent, 0, len(m.StreamEvents[streamID]))
	for _, e := range m.StreamEvents[streamID] {
		if slices.ContainsFunc(jtis, func(jti string) bool {
			return e.JWTID == jti
		}) {
			continue
		}
		remainingEvents = append(remainingEvents, e)
	}

	m.StreamEvents[streamID] = remainingEvents
	return nil
}

func (m *SSFManager) AcknowledgeErrors(_ context.Context, streamID string, errs map[string]goidc.SSFEventError, opts goidc.SSFAcknowledgementOptions) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	remainingEvents := make([]goidc.SSFEvent, 0, len(m.StreamEvents[streamID]))
	for _, e := range m.StreamEvents[streamID] {
		if _, hasError := errs[e.JWTID]; hasError {
			continue
		}
		remainingEvents = append(remainingEvents, e)
	}

	m.StreamEvents[streamID] = remainingEvents
	return nil
}

func (m *SSFManager) Trigger(_ context.Context, streamID string, opts goidc.SSFStreamVerificationOptions) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.Streams[streamID]; !exists {
		return errors.New("entity not found")
	}

	m.StreamVerifications[streamID] = opts
	return nil
}

// compareSSFSubjects compares two SSFSubjects according to the subject matching rules.
// [SSF 1.0 §8.1.3.1].
func compareSSFSubjects(a, b *goidc.SSFSubject) bool {
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
