// Package timeutil provides utilities for working with time in a consistent
// manner. All time-related functions ensure the time is represented
// in UTC, helping to avoid issues related to time zone discrepancies.
package timeutil

import "time"

func TimestampNow() int {
	return int(time.Now().Unix())
}

func Timestamp(t time.Time) int {
	return int(t.Unix())
}

func Now() time.Time {
	return time.Now().UTC()
}
