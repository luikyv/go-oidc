package timeutil

import "time"

// TODO: Remove this.
func TimestampNow() int {
	return int(time.Now().Unix())
}
