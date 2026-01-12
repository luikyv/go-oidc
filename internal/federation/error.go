package federation

import "errors"

// ErrCircularDependency is returned when a circular dependency is detected
// while building a trust chain.
var ErrCircularDependency = errors.New("circular dependency detected in trust chain")
