package timeutil

import (
	"testing"
	"time"
)

func TestTimestampNow(t *testing.T) {
	before := int(time.Now().UTC().Unix())
	ts := TimestampNow()
	after := int(time.Now().UTC().Unix())

	if ts < before || ts > after {
		t.Errorf("TimestampNow() = %d, want between %d and %d", ts, before, after)
	}
}

func TestNow_IsUTC(t *testing.T) {
	now := Now()
	if now.Location() != time.UTC {
		t.Errorf("Now().Location() = %v, want UTC", now.Location())
	}
}

func TestNow_IsRecent(t *testing.T) {
	before := time.Now().UTC()
	now := Now()
	after := time.Now().UTC()

	if now.Before(before) || now.After(after) {
		t.Errorf("Now() = %v, want between %v and %v", now, before, after)
	}
}
