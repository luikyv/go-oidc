package federation

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
)

type metadataOperators[T any] struct {
	Value      nullable[T] `json:"value"`
	Add        T           `json:"add"`
	Default    T           `json:"default"`
	OneOf      []T         `json:"one_of"`
	SubsetOf   T           `json:"subset_of"`
	SupersetOf T           `json:"superset_of"`
	Essential  bool        `json:"essential"`
}

func (ops metadataOperators[T]) validate() error {
	// Operators are validated in the reverse order of application (see apply method).
	// This ensures that operators applied later can rely on constraints from earlier ones.
	if err := ops.validateEssential(); err != nil {
		return err
	}

	if err := ops.validateSupersetOf(); err != nil {
		return err
	}

	if err := ops.validateSubsetOf(); err != nil {
		return err
	}

	if err := ops.validateOneOf(); err != nil {
		return err
	}

	if err := ops.validateOneOf(); err != nil {
		return err
	}

	if err := ops.validateDefault(); err != nil {
		return err
	}

	if err := ops.validateAdd(); err != nil {
		return err
	}

	if err := ops.validateValue(); err != nil {
		return err
	}

	return nil
}

func (ops metadataOperators[T]) validateValue() error {
	if !ops.isValueSet() {
		return nil
	}

	if ops.isAddSet() || ops.isDefaultSet() || ops.isOneOfSet() || ops.isSubsetOfSet() || ops.isSupersetOfSet() {
		return errors.New("operator 'value' cannot be combined with other operators than 'essential'")
	}

	return nil
}

func (ops metadataOperators[T]) validateAdd() error {
	if !ops.isAddSet() {
		return nil
	}

	if !isSlice(ops.Add) {
		return fmt.Errorf("operator 'add' must be an array, but found %v", ops.Add)
	}

	if ops.isOneOfSet() {
		return errors.New("operator 'add' cannot be combined with 'one_of'")
	}

	if ops.isSubsetOfSet() && !isSubset(ops.Add, ops.SubsetOf) {
		return fmt.Errorf("operator 'add' must be a subset of 'subset_of'. add: %v, subset_of: %v", ops.Add, ops.SubsetOf)
	}

	if ops.isSupersetOfSet() && !isSuperset(ops.Add, ops.SupersetOf) {
		return fmt.Errorf("operator 'add' must be a superset of 'superset_of'. add: %v, superset_of: %v", ops.Add, ops.SubsetOf)
	}

	return nil
}

func (ops metadataOperators[T]) validateDefault() error {
	if !ops.isDefaultSet() {
		return nil
	}

	if ops.isOneOfSet() && !deepContains(ops.OneOf, ops.Default) {
		return fmt.Errorf("operator 'default' must be among the values of 'one_of'. default: %v, one_of: %v", ops.Default, ops.OneOf)
	}

	if ops.isSubsetOfSet() && !isSubset(ops.Default, ops.SubsetOf) {
		return fmt.Errorf("operator 'default' must be a subset of 'subset_of'. default: %v, subset_of: %v", ops.Default, ops.SubsetOf)
	}

	if ops.isSupersetOfSet() && !isSuperset(ops.Default, ops.SupersetOf) {
		return fmt.Errorf("operator 'default' must be a superset of 'superset_of'. default: %v, superset_of: %v", ops.Default, ops.SupersetOf)
	}

	return nil
}

func (ops metadataOperators[T]) validateOneOf() error {
	if !ops.isOneOfSet() {
		return nil
	}

	if ops.isSubsetOfSet() || ops.isSupersetOfSet() {
		return errors.New("operator 'one_of' cannot be combined with 'subset_of' or 'superset_of'")
	}

	return nil
}

func (ops metadataOperators[T]) validateSubsetOf() error {
	if !ops.isSubsetOfSet() {
		return nil
	}

	if !isSlice(ops.SubsetOf) {
		return fmt.Errorf("operator 'subset_of' must be an array, but found %v", ops.SubsetOf)
	}

	if ops.isSupersetOfSet() && !isSuperset(ops.SubsetOf, ops.SupersetOf) {
		return fmt.Errorf("operator 'subset_of' must be a superset of 'superset_of'. subset_of: %v, superset_of: %v", ops.SubsetOf, ops.SupersetOf)
	}

	return nil
}

func (ops metadataOperators[T]) validateSupersetOf() error {
	if !ops.isSupersetOfSet() {
		return nil
	}

	if !isSlice(ops.SupersetOf) {
		return fmt.Errorf("operator 'superset_of' must be an array, but found %v", ops.SupersetOf)
	}

	return nil
}

func (ops metadataOperators[T]) validateEssential() error {
	return nil
}

func (ops metadataOperators[T]) apply(value T) (T, error) {
	var zero T
	var err error

	value, err = ops.applyValue(value)
	if err != nil {
		return zero, err
	}

	value, err = ops.applyAdd(value)
	if err != nil {
		return zero, err
	}

	value, err = ops.applyDefault(value)
	if err != nil {
		return zero, err
	}

	value, err = ops.applyOneOf(value)
	if err != nil {
		return zero, err
	}

	value, err = ops.applySubsetOf(value)
	if err != nil {
		return zero, err
	}

	value, err = ops.applySupersetOf(value)
	if err != nil {
		return zero, err
	}

	value, err = ops.applyEssential(value)
	if err != nil {
		return zero, err
	}

	return value, nil
}

func (ops metadataOperators[T]) applyValue(value T) (T, error) {
	if !ops.isValueSet() {
		return value, nil
	}

	return ops.Value.Value, nil
}

func (ops metadataOperators[T]) applyAdd(value T) (T, error) {
	if !ops.isAddSet() {
		return value, nil
	}

	return mergeSlices(value, ops.Add), nil
}

func (ops metadataOperators[T]) applyDefault(value T) (T, error) {
	if !ops.isDefaultSet() {
		return value, nil
	}

	var zero T
	if reflect.DeepEqual(value, zero) {
		return ops.Default, nil
	}
	return value, nil
}

func (ops metadataOperators[T]) applyOneOf(value T) (T, error) {
	if !ops.isOneOfSet() {
		return value, nil
	}

	var zero T
	if !deepContains(ops.OneOf, value) {
		return zero, fmt.Errorf("value is not one of the values in 'one_of'. value: %v, one_of: %v", value, ops.OneOf)
	}

	return value, nil
}

func (ops metadataOperators[T]) applySubsetOf(value T) (T, error) {
	if !ops.isSubsetOfSet() {
		return value, nil
	}

	var zero T
	// TODO: Should it return an error or the intersection of the two slices?
	if !isSubset(value, ops.SubsetOf) {
		return zero, fmt.Errorf("value is not a subset of the values in 'subset_of'. value: %v, subset_of: %v", value, ops.SubsetOf)
	}

	return value, nil
}

func (ops metadataOperators[T]) applySupersetOf(value T) (T, error) {
	if !ops.isSupersetOfSet() {
		return value, nil
	}

	var zero T
	if !isSuperset(value, ops.SupersetOf) {
		return zero, fmt.Errorf("value is not a superset of the values in 'superset_of'. value: %v, superset_of: %v", value, ops.SupersetOf)
	}

	return value, nil
}

func (ops metadataOperators[T]) applyEssential(value T) (T, error) {
	if !ops.Essential {
		return value, nil
	}

	// TODO: What if value is an empty slice?
	var zero T
	if reflect.DeepEqual(value, zero) {
		return zero, errors.New("value is essential but is not present")
	}

	return value, nil
}

func (highOps metadataOperators[T]) merge(lowOps metadataOperators[T]) (metadataOperators[T], error) {
	var err error

	highOps.Value, err = highOps.mergeValue(lowOps)
	if err != nil {
		return metadataOperators[T]{}, err
	}

	highOps.Add, err = highOps.mergeAdd(lowOps)
	if err != nil {
		return metadataOperators[T]{}, err
	}

	highOps.Default, err = highOps.mergeDefault(lowOps)
	if err != nil {
		return metadataOperators[T]{}, err
	}

	highOps.OneOf, err = highOps.mergeOneOf(lowOps)
	if err != nil {
		return metadataOperators[T]{}, err
	}

	highOps.SubsetOf, err = highOps.mergeSubsetOf(lowOps)
	if err != nil {
		return metadataOperators[T]{}, err
	}

	highOps.SupersetOf, err = highOps.mergeSupersetOf(lowOps)
	if err != nil {
		return metadataOperators[T]{}, err
	}

	highOps.Essential, err = highOps.mergeEssential(lowOps)
	if err != nil {
		return metadataOperators[T]{}, err
	}

	return highOps, nil
}

func (highOps metadataOperators[T]) mergeValue(lowOps metadataOperators[T]) (nullable[T], error) {
	if !highOps.isValueSet() {
		return lowOps.Value, nil
	}

	if !lowOps.isValueSet() {
		return highOps.Value, nil
	}

	if !compare(highOps.Value.Value, lowOps.Value.Value) {
		return nullable[T]{}, fmt.Errorf("cannot merge operator 'value' with mismatch %v, %v", highOps.Value.Value, lowOps.Value.Value)
	}

	return highOps.Value, nil
}

func (highOps metadataOperators[T]) mergeAdd(lowOps metadataOperators[T]) (T, error) {
	if !highOps.isAddSet() {
		return lowOps.Add, nil
	}

	if !lowOps.isAddSet() {
		return highOps.Add, nil
	}

	return mergeSlices(highOps.Add, lowOps.Add), nil
}

func (highOps metadataOperators[T]) mergeDefault(lowOps metadataOperators[T]) (T, error) {
	if !highOps.isDefaultSet() {
		return lowOps.Default, nil
	}

	if !lowOps.isDefaultSet() {
		return highOps.Default, nil
	}

	if !compare(highOps.Default, lowOps.Default) {
		var zero T
		return zero, fmt.Errorf("cannot merge operator 'default' with mismatch %v, %v", highOps.Default, lowOps.Default)
	}

	return highOps.Default, nil
}

func (highOps metadataOperators[T]) mergeOneOf(lowOps metadataOperators[T]) ([]T, error) {
	if !highOps.isOneOfSet() {
		return lowOps.OneOf, nil
	}

	if !lowOps.isOneOfSet() {
		return highOps.OneOf, nil
	}

	oneOf := intersectSlices(highOps.OneOf, lowOps.OneOf)
	if len(oneOf) == 0 {
		return nil, fmt.Errorf("cannot merge operator 'one_of' %v, %v", highOps.OneOf, lowOps.OneOf)
	}

	return oneOf, nil
}

func (highOps metadataOperators[T]) mergeSubsetOf(lowOps metadataOperators[T]) (T, error) {
	if !highOps.isSubsetOfSet() {
		return lowOps.SubsetOf, nil
	}

	if !lowOps.isSubsetOfSet() {
		return highOps.SubsetOf, nil
	}

	subsetOf := intersectSlices(highOps.SubsetOf, lowOps.SubsetOf)
	var zero T
	// NOTE: This won't work if len(subsetOf) == 0.
	if reflect.DeepEqual(subsetOf, zero) {
		return zero, fmt.Errorf("cannot merge operator 'subset_of' %v, %v", highOps.SubsetOf, lowOps.SubsetOf)
	}

	return subsetOf, nil
}

func (highOps metadataOperators[T]) mergeSupersetOf(lowOps metadataOperators[T]) (T, error) {
	if !highOps.isSupersetOfSet() {
		return lowOps.SupersetOf, nil
	}

	if !lowOps.isSupersetOfSet() {
		return highOps.SupersetOf, nil
	}

	return mergeSlices(highOps.SupersetOf, lowOps.SupersetOf), nil
}

func (highOps metadataOperators[T]) mergeEssential(lowOps metadataOperators[T]) (bool, error) {
	return highOps.Essential || lowOps.Essential, nil
}

func (ops metadataOperators[T]) isValueSet() bool {
	return ops.Value.Set
}

func (ops metadataOperators[T]) isAddSet() bool {
	var zero T
	return !reflect.DeepEqual(ops.Add, zero)
}

func (ops metadataOperators[T]) isDefaultSet() bool {
	var zero T
	return !reflect.DeepEqual(ops.Default, zero)
}

func (ops metadataOperators[T]) isOneOfSet() bool {
	return ops.OneOf != nil
}

func (ops metadataOperators[T]) isSubsetOfSet() bool {
	var zero T
	return !reflect.DeepEqual(ops.SubsetOf, zero)
}

func (ops metadataOperators[T]) isSupersetOfSet() bool {
	var zero T
	return !reflect.DeepEqual(ops.SupersetOf, zero)
}

type nullable[T any] struct {
	Set   bool
	Value T
}

// mergeSlices merges two slices and removes duplicates.
func mergeSlices[T any](slice1, slice2 T) T {

	if !isSlice(slice1) || !isSlice(slice2) {
		// TODO: Shouldn't panic.
		panic("mergeSlices: both arguments must be slices")
	}

	v1 := reflect.ValueOf(slice1)
	v2 := reflect.ValueOf(slice2)
	result := reflect.MakeSlice(v1.Type(), 0, v1.Len()+v2.Len())
	// Use a map to track unique elements.
	unique := make(map[interface{}]struct{})

	for i := 0; i < v1.Len(); i++ {
		elem := v1.Index(i).Interface()
		if _, exists := unique[elem]; !exists {
			unique[elem] = struct{}{}
			result = reflect.Append(result, v1.Index(i))
		}
	}

	for i := 0; i < v2.Len(); i++ {
		elem := v2.Index(i).Interface()
		if _, exists := unique[elem]; !exists {
			unique[elem] = struct{}{}
			result = reflect.Append(result, v2.Index(i))
		}
	}

	return result.Interface().(T)
}

func intersectSlices[T any](slice1, slice2 T) T {

	if !isSlice(slice1) || !isSlice(slice2) {
		// TODO: Shouldn't panic.
		panic("intersectSlices: both arguments must be slices")
	}

	v1 := reflect.ValueOf(slice1)
	v2 := reflect.ValueOf(slice2)
	result := reflect.MakeSlice(v1.Type(), 0, 0)
	// Use a map to track unique elements.
	unique := make(map[any]struct{})

	for i := 0; i < v1.Len(); i++ {
		elem := v1.Index(i).Interface()
		if _, exists := unique[elem]; !exists {
			unique[elem] = struct{}{}
		}
	}

	for i := 0; i < v2.Len(); i++ {
		elem := v2.Index(i).Interface()
		if _, exists := unique[elem]; exists {
			unique[elem] = struct{}{}
			result = reflect.Append(result, v2.Index(i))
		}
	}

	if result.Len() == 0 {
		var zero T
		return zero
	}

	return result.Interface().(T)
}

func isSuperset[T any](superset, subset T) bool {
	return isSubset(subset, superset)
}

func isSubset[T any](subset, superset T) bool {
	if !isSlice(subset) || !isSlice(superset) {
		return false
	}

	subsetV := reflect.ValueOf(subset)
	supersetV := reflect.ValueOf(superset)

	// Use a map to track elements in superset.
	set := make(map[any]struct{})
	for i := 0; i < supersetV.Len(); i++ {
		set[supersetV.Index(i).Interface()] = struct{}{}
	}

	// Check if all elements of slice1 are in slice2.
	for i := 0; i < subsetV.Len(); i++ {
		if _, exists := set[subsetV.Index(i).Interface()]; !exists {
			return false
		}
	}

	return true
}

func isSlice(v any) bool {
	return reflect.ValueOf(v).Kind() == reflect.Slice
}

func deepContains[T any](s []T, e T) bool {
	return slices.ContainsFunc(s, func(se T) bool {
		return reflect.DeepEqual(se, e)
	})
}

func compare(x, y any) bool {
	if isSlice(x) && isSlice(y) {
		return compareSlices(x, y)
	}

	return reflect.DeepEqual(x, y)
}

func compareSlices(x, y any) bool {
	vx, vy := reflect.ValueOf(x), reflect.ValueOf(y)
	if vx.Len() != vy.Len() {
		return false
	}

	match := make(map[any]struct{})
	for i := 0; i < vx.Len(); i++ {
		match[vx.Index(i).Interface()] = struct{}{}
	}

	for i := 0; i < vy.Len(); i++ {
		val := vy.Index(i).Interface()
		if _, ok := match[val]; !ok {
			return false
		}
	}

	return true
}
