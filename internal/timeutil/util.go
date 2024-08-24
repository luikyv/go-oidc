package timeutil

import "time"

func TimestampNow() int {
	return int(time.Now().Unix())
}
