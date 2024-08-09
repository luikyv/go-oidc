package inmemory

// Return the first element in a slice for which the condition is true.
// If no element is found, 'ok' is set to false.
func findFirst[T interface{}](slice []T, condition func(T) bool) (element T, ok bool) {
	for _, element = range slice {
		if condition(element) {
			return element, true
		}
	}

	return element, false
}
