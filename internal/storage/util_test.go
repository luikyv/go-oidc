package storage

import "testing"

func TestRemoveOldest(t *testing.T) {
	// Given.
	type session struct {
		ID        string
		CreatedAt int
	}
	sessions := map[string]session{
		"session1": {ID: "session1", CreatedAt: 100},
		"session2": {ID: "session2", CreatedAt: 50}, // Oldest.
		"session3": {ID: "session3", CreatedAt: 150},
	}

	// When.
	removeOldest(sessions, func(s session) int {
		return s.CreatedAt
	})

	// Then.
	if _, exists := sessions["session2"]; exists {
		t.Errorf("expected session2 to be removed, but it still exists")
	}

	// Remaining sessions should be session1 and session3
	if len(sessions) != 2 {
		t.Errorf("expected 2 sessions remaining, got %d", len(sessions))
	}
}
