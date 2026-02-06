package ssf

import (
	"encoding/json"
	"testing"
)

func TestAudiences_MarshalJSON_SingleAudience(t *testing.T) {
	// Given.
	auds := Audiences{"https://receiver.example.com"}

	// When.
	data, err := json.Marshal(auds)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Single audience should marshal as string, not array.
	want := `"https://receiver.example.com"`
	if string(data) != want {
		t.Errorf("got %s, want %s", string(data), want)
	}
}

func TestAudiences_MarshalJSON_MultipleAudiences(t *testing.T) {
	// Given.
	auds := Audiences{"https://receiver1.example.com", "https://receiver2.example.com"}

	// When.
	data, err := json.Marshal(auds)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Multiple audiences should marshal as array.
	want := `["https://receiver1.example.com","https://receiver2.example.com"]`
	if string(data) != want {
		t.Errorf("got %s, want %s", string(data), want)
	}
}

func TestAudiences_MarshalJSON_EmptyAudiences(t *testing.T) {
	// Given.
	auds := Audiences{}

	// When.
	data, err := json.Marshal(auds)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Empty audiences should marshal as empty array.
	want := `[]`
	if string(data) != want {
		t.Errorf("got %s, want %s", string(data), want)
	}
}
