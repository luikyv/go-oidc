package storage

// findFirst returns the first element in a slice for which the condition is true.
// If no element is found, 'ok' is set to false.
func findFirst[T any](slice []T, condition func(T) bool) (element T, ok bool) {
	for _, element = range slice {
		if condition(element) {
			return element, true
		}
	}

	return element, false
}

func removeOldest[T any](m map[string]T, createdAtFunc func(T) int) {
	var oldestKey string
	var oldestCreatedAt int

	for key, value := range m {
		createdAt := createdAtFunc(value)
		if oldestCreatedAt == 0 || createdAt < oldestCreatedAt {
			oldestKey = key
			oldestCreatedAt = createdAt
		}
	}

	delete(m, oldestKey)
}
