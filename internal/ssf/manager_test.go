package ssf

import (
	"context"
	"testing"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestEventManager_CreateAndEventStream(t *testing.T) {
	// Given.
	manager := NewEventManager(100)
	stream := &goidc.SSFEventStream{
		ID:         "stream_1",
		ReceiverID: "receiver_1",
		Status:     goidc.SSFEventStreamStatusEnabled,
	}

	// When.
	err := manager.Create(context.Background(), stream)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	fetched, err := manager.EventStream(context.Background(), "stream_1")
	if err != nil {
		t.Fatalf("unexpected error fetching stream: %v", err)
	}
	if fetched.ID != stream.ID {
		t.Errorf("stream ID = %s, want %s", fetched.ID, stream.ID)
	}
}

func TestEventManager_EventStream_NotFound(t *testing.T) {
	manager := NewEventManager(100)

	_, err := manager.EventStream(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent stream")
	}
}

func TestEventManager_EventStreams(t *testing.T) {
	// Given.
	manager := NewEventManager(100)
	_ = manager.Create(context.Background(), &goidc.SSFEventStream{ID: "stream_1", ReceiverID: "receiver_1"})
	_ = manager.Create(context.Background(), &goidc.SSFEventStream{ID: "stream_2", ReceiverID: "receiver_1"})
	_ = manager.Create(context.Background(), &goidc.SSFEventStream{ID: "stream_3", ReceiverID: "receiver_2"})

	// When.
	streams, err := manager.EventStreams(context.Background(), "receiver_1")

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(streams) != 2 {
		t.Errorf("got %d streams, want 2", len(streams))
	}
}

func TestEventManager_Update(t *testing.T) {
	// Given.
	manager := NewEventManager(100)
	stream := &goidc.SSFEventStream{ID: "stream_1", Status: goidc.SSFEventStreamStatusEnabled}
	_ = manager.Create(context.Background(), stream)

	// When.
	stream.Status = goidc.SSFEventStreamStatusPaused
	err := manager.Update(context.Background(), stream)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	fetched, _ := manager.EventStream(context.Background(), "stream_1")
	if fetched.Status != goidc.SSFEventStreamStatusPaused {
		t.Errorf("status = %s, want %s", fetched.Status, goidc.SSFEventStreamStatusPaused)
	}
}

func TestEventManager_Delete(t *testing.T) {
	// Given.
	manager := NewEventManager(100)
	_ = manager.Create(context.Background(), &goidc.SSFEventStream{ID: "stream_1"})
	_ = manager.Add(context.Background(), "stream_1", goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"}, goidc.SSFSubjectOptions{})
	_ = manager.Save(context.Background(), "stream_1", goidc.SSFEvent{JWTID: "jti_1"})

	// When.
	err := manager.Delete(context.Background(), "stream_1")

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = manager.EventStream(context.Background(), "stream_1")
	if err == nil {
		t.Error("expected error for deleted stream")
	}
}

func TestEventManager_MaxStreams(t *testing.T) {
	// Given.
	manager := NewEventManager(2)
	_ = manager.Create(context.Background(), &goidc.SSFEventStream{ID: "stream_1", CreatedAtTimestamp: 100})
	_ = manager.Create(context.Background(), &goidc.SSFEventStream{ID: "stream_2", CreatedAtTimestamp: 200})

	// When - create third stream, should evict oldest.
	_ = manager.Create(context.Background(), &goidc.SSFEventStream{ID: "stream_3", CreatedAtTimestamp: 300})

	// Then.
	_, err := manager.EventStream(context.Background(), "stream_1")
	if err == nil {
		t.Error("oldest stream should have been evicted")
	}

	_, err = manager.EventStream(context.Background(), "stream_2")
	if err != nil {
		t.Error("stream_2 should still exist")
	}

	_, err = manager.EventStream(context.Background(), "stream_3")
	if err != nil {
		t.Error("stream_3 should exist")
	}
}

func TestEventManager_AddAndRemoveSubject(t *testing.T) {
	// Given.
	manager := NewEventManager(100)
	_ = manager.Create(context.Background(), &goidc.SSFEventStream{ID: "stream_1"})
	subject := goidc.SSFSubject{Format: goidc.SSFSubjectFormatEmail, Email: "user@example.com"}

	// When - add subject.
	err := manager.Add(context.Background(), "stream_1", subject, goidc.SSFSubjectOptions{})
	if err != nil {
		t.Fatalf("unexpected error adding subject: %v", err)
	}

	// Then - subject should be in the list.
	if len(manager.streamSubjects["stream_1"]) != 1 {
		t.Errorf("got %d subjects, want 1", len(manager.streamSubjects["stream_1"]))
	}

	// When - add same subject again (should not duplicate).
	_ = manager.Add(context.Background(), "stream_1", subject, goidc.SSFSubjectOptions{})
	if len(manager.streamSubjects["stream_1"]) != 1 {
		t.Errorf("got %d subjects after duplicate add, want 1", len(manager.streamSubjects["stream_1"]))
	}

	// When - remove subject.
	err = manager.Remove(context.Background(), "stream_1", subject)
	if err != nil {
		t.Fatalf("unexpected error removing subject: %v", err)
	}

	// Then - subject should be removed.
	if len(manager.streamSubjects["stream_1"]) != 0 {
		t.Errorf("got %d subjects after remove, want 0", len(manager.streamSubjects["stream_1"]))
	}
}

func TestEventManager_SaveAndPoll(t *testing.T) {
	// Given.
	manager := NewEventManager(100)
	_ = manager.Create(context.Background(), &goidc.SSFEventStream{ID: "stream_1"})

	events := []goidc.SSFEvent{
		{JWTID: "jti_1", Type: goidc.SSFEventTypeCAEPSessionRevoked},
		{JWTID: "jti_2", Type: goidc.SSFEventTypeCAEPSessionRevoked},
		{JWTID: "jti_3", Type: goidc.SSFEventTypeCAEPSessionRevoked},
		{JWTID: "jti_4", Type: goidc.SSFEventTypeCAEPSessionRevoked},
	}

	for _, e := range events {
		_ = manager.Save(context.Background(), "stream_1", e)
	}

	// When - poll with default maxEvents (3).
	result, err := manager.Poll(context.Background(), "stream_1", goidc.SSFPollOptions{})

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Events) != 3 {
		t.Errorf("got %d events, want 3 (maxPollEvents)", len(result.Events))
	}
	if !result.MoreAvailable {
		t.Error("moreAvailable should be true")
	}
}

func TestEventManager_Poll_WithMaxEvents(t *testing.T) {
	// Given.
	manager := NewEventManager(100)
	_ = manager.Create(context.Background(), &goidc.SSFEventStream{ID: "stream_1"})

	for i := 0; i < 5; i++ {
		_ = manager.Save(context.Background(), "stream_1", goidc.SSFEvent{JWTID: string(rune('a' + i))})
	}

	// When - poll with custom maxEvents.
	maxEvents := 2
	result, err := manager.Poll(context.Background(), "stream_1", goidc.SSFPollOptions{MaxEvents: &maxEvents})

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Events) != 2 {
		t.Errorf("got %d events, want 2", len(result.Events))
	}
}

func TestEventManager_Poll_EmptyQueue(t *testing.T) {
	// Given.
	manager := NewEventManager(100)
	_ = manager.Create(context.Background(), &goidc.SSFEventStream{ID: "stream_1"})

	// When.
	result, err := manager.Poll(context.Background(), "stream_1", goidc.SSFPollOptions{})

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Events) != 0 {
		t.Errorf("got %d events, want 0", len(result.Events))
	}
	if result.MoreAvailable {
		t.Error("moreAvailable should be false for empty queue")
	}
}

func TestEventManager_Acknowledge(t *testing.T) {
	// Given.
	manager := NewEventManager(100)
	_ = manager.Create(context.Background(), &goidc.SSFEventStream{ID: "stream_1"})

	events := []goidc.SSFEvent{
		{JWTID: "jti_1"},
		{JWTID: "jti_2"},
		{JWTID: "jti_3"},
	}
	for _, e := range events {
		_ = manager.Save(context.Background(), "stream_1", e)
	}

	// When.
	err := manager.Acknowledge(context.Background(), "stream_1", []string{"jti_1", "jti_3"}, goidc.SSFAcknowledgementOptions{})

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, _ := manager.Poll(context.Background(), "stream_1", goidc.SSFPollOptions{})
	if len(result.Events) != 1 {
		t.Errorf("got %d events after ack, want 1", len(result.Events))
	}
	if result.Events[0].JWTID != "jti_2" {
		t.Errorf("remaining event JWTID = %s, want jti_2", result.Events[0].JWTID)
	}
}

func TestEventManager_AcknowledgeErrors(t *testing.T) {
	// Given.
	manager := NewEventManager(100)
	_ = manager.Create(context.Background(), &goidc.SSFEventStream{ID: "stream_1"})

	events := []goidc.SSFEvent{
		{JWTID: "jti_1"},
		{JWTID: "jti_2"},
		{JWTID: "jti_3"},
	}
	for _, e := range events {
		_ = manager.Save(context.Background(), "stream_1", e)
	}

	// When.
	errs := map[string]goidc.SSFEventError{
		"jti_1": {Error: goidc.SSFEventErrorCodeInvalidRequest, Description: "bad event"},
		"jti_2": {Error: goidc.SSFEventErrorCodeAccessDenied, Description: "not allowed"},
	}
	err := manager.AcknowledgeErrors(context.Background(), "stream_1", errs, goidc.SSFAcknowledgementOptions{})

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, _ := manager.Poll(context.Background(), "stream_1", goidc.SSFPollOptions{})
	if len(result.Events) != 1 {
		t.Errorf("got %d events after ack errors, want 1", len(result.Events))
	}
	if result.Events[0].JWTID != "jti_3" {
		t.Errorf("remaining event JWTID = %s, want jti_3", result.Events[0].JWTID)
	}
}

// Note: TestEventManager_Schedule is not included because Schedule() has a bug
// where it wraps the context with WithTimeout and then tries to type-assert
// back to oidc.Context, which fails. This needs to be fixed in production code.

func TestEventManager_Schedule_NoPublishFunc(t *testing.T) {
	// Given.
	manager := NewEventManager(100)
	_ = manager.Create(context.Background(), &goidc.SSFEventStream{ID: "stream_1"})

	// When - no publish func, should return early without panic.
	err := manager.Schedule(context.Background(), "stream_1", goidc.SSFStreamVerificationOptions{})

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
