package federation

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
)

type metadataPolicyPrimitiveOps[T any] struct {
	Value     primitiveOperatorValue[T]     `json:"value"`
	Default   primitiveOperatorDefault[T]   `json:"default"`
	OneOf     primitiveOperatorOneOf[T]     `json:"one_of"`
	Essential primitiveOperatorEssential[T] `json:"essential"`
}

func (highOps metadataPolicyPrimitiveOps[T]) merge(lowOps metadataPolicyPrimitiveOps[T]) (metadataPolicyPrimitiveOps[T], error) {
	valueOp, err := highOps.Value.merge(lowOps.Value)
	if err != nil {
		return metadataPolicyPrimitiveOps[T]{}, err
	}
	highOps.Value = valueOp

	defaultOp, err := highOps.Default.merge(lowOps.Default)
	if err != nil {
		return metadataPolicyPrimitiveOps[T]{}, err
	}
	highOps.Default = defaultOp

	oneOfOp, err := highOps.OneOf.merge(lowOps.OneOf)
	if err != nil {
		return metadataPolicyPrimitiveOps[T]{}, err
	}
	highOps.OneOf = oneOfOp

	essentialOp, err := highOps.Essential.merge(lowOps.Essential)
	if err != nil {
		return metadataPolicyPrimitiveOps[T]{}, err
	}
	highOps.Essential = essentialOp

	return highOps, nil
}

func (ops metadataPolicyPrimitiveOps[T]) apply(field T) (T, error) {
	var defaultT T

	field, err := ops.Value.apply(field)
	if err != nil {
		return defaultT, err
	}

	field, err = ops.Default.apply(field)
	if err != nil {
		return defaultT, err
	}

	field, err = ops.OneOf.apply(field)
	if err != nil {
		return defaultT, err
	}

	field, err = ops.Essential.apply(field)
	if err != nil {
		return defaultT, err
	}

	return field, nil
}

type metadataPolicySliceOps[T any] struct {
	Value      sliceOperatorValue[T]      `json:"value"`
	Add        sliceOperatorAdd[T]        `json:"add"`
	Default    sliceOperatorDefault[T]    `json:"default"`
	SubsetOf   sliceOperatorSubsetOf[T]   `json:"subset_of"`
	SupersetOf sliceOperatorSupersetOf[T] `json:"superset_of"`
	Essential  sliceOperatorEssential[T]  `json:"essential"`
}

func (highOps metadataPolicySliceOps[T]) merge(lowOps metadataPolicySliceOps[T]) (metadataPolicySliceOps[T], error) {
	valueOp, err := highOps.Value.merge(lowOps.Value)
	if err != nil {
		return metadataPolicySliceOps[T]{}, err
	}
	highOps.Value = valueOp

	addOp, err := highOps.Add.merge(lowOps.Add)
	if err != nil {
		return metadataPolicySliceOps[T]{}, err
	}
	highOps.Add = addOp

	defaultOp, err := highOps.Default.merge(lowOps.Default)
	if err != nil {
		return metadataPolicySliceOps[T]{}, err
	}
	highOps.Default = defaultOp

	subsetOf, err := highOps.SubsetOf.merge(lowOps.SubsetOf)
	if err != nil {
		return metadataPolicySliceOps[T]{}, err
	}
	highOps.SubsetOf = subsetOf

	supersetOf, err := highOps.SupersetOf.merge(lowOps.SupersetOf)
	if err != nil {
		return metadataPolicySliceOps[T]{}, err
	}
	highOps.SupersetOf = supersetOf

	essentialOp, err := highOps.Essential.merge(lowOps.Essential)
	if err != nil {
		return metadataPolicySliceOps[T]{}, err
	}
	highOps.Essential = essentialOp

	return highOps, nil
}

func (ops metadataPolicySliceOps[T]) apply(field []T) ([]T, error) {
	field, err := ops.Value.apply(field)
	if err != nil {
		return nil, err
	}

	field, err = ops.Add.apply(field)
	if err != nil {
		return nil, err
	}

	field, err = ops.Default.apply(field)
	if err != nil {
		return nil, err
	}

	field, err = ops.SubsetOf.apply(field)
	if err != nil {
		return nil, err
	}

	field, err = ops.SupersetOf.apply(field)
	if err != nil {
		return nil, err
	}

	field, err = ops.Essential.apply(field)
	if err != nil {
		return nil, err
	}

	return field, nil
}

type primitiveOperatorValue[T any] struct {
	isSet bool
	value T
}

func (p *primitiveOperatorValue[T]) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		p.isSet = true
		return nil
	}

	var t T
	if err := json.Unmarshal(data, &t); err != nil {
		return err
	}

	p.isSet = true
	p.value = t
	return nil
}

func (highOp primitiveOperatorValue[T]) merge(lowOp primitiveOperatorValue[T]) (primitiveOperatorValue[T], error) {
	if !lowOp.isSet {
		return highOp, nil
	}

	if !highOp.isSet {
		return lowOp, nil
	}

	if !reflect.DeepEqual(highOp.value, lowOp.value) {
		return primitiveOperatorValue[T]{}, errors.New("operator 'value' was informed by both policies but the values are different")
	}

	return highOp, nil
}

func (op primitiveOperatorValue[T]) apply(field T) (T, error) {
	if !op.isSet {
		return field, nil
	}

	return op.value, nil
}

type primitiveOperatorDefault[T any] struct {
	value T
}

func (p *primitiveOperatorDefault[T]) UnmarshalJSON(data []byte) error {
	var t T
	if err := json.Unmarshal(data, &t); err != nil {
		return err
	}

	p.value = t
	return nil
}

func (highOp primitiveOperatorDefault[T]) merge(lowOp primitiveOperatorDefault[T]) (primitiveOperatorDefault[T], error) {
	var zeroValue T
	if reflect.DeepEqual(lowOp.value, zeroValue) {
		return highOp, nil
	}

	if reflect.DeepEqual(highOp.value, zeroValue) {
		return lowOp, nil
	}

	if !reflect.DeepEqual(highOp.value, lowOp.value) {
		return primitiveOperatorDefault[T]{}, errors.New("operator 'default' was informed by both policies but the values are different")
	}

	return highOp, nil
}

func (op primitiveOperatorDefault[T]) apply(field T) (T, error) {
	var zeroValue T
	if reflect.DeepEqual(op.value, zeroValue) {
		return field, nil
	}

	if reflect.DeepEqual(field, zeroValue) {
		return op.value, nil
	}

	return field, nil
}

type primitiveOperatorOneOf[T any] []T

func (highOp primitiveOperatorOneOf[T]) merge(lowOp primitiveOperatorOneOf[T]) (primitiveOperatorOneOf[T], error) {
	if len(lowOp) == 0 {
		return highOp, nil
	}

	if len(highOp) == 0 {
		return lowOp, nil
	}

	var oneOf []T
	for _, value := range lowOp {
		if deepContains(highOp, value) {
			oneOf = append(oneOf, value)
		}
	}

	if len(oneOf) == 0 {
		return nil, errors.New("operator 'oneOf' was informed by both policies but the values have no intersection")
	}

	return oneOf, nil
}

func (op primitiveOperatorOneOf[T]) apply(field T) (T, error) {
	if len(op) == 0 {
		return field, nil
	}

	if !deepContains(op, field) {
		var defaultT T
		return defaultT, fmt.Errorf("field %v is not one of %v", field, op)
	}

	return field, nil
}

type sliceOperatorValue[T any] struct {
	isSet bool
	value []T
}

func (p *sliceOperatorValue[T]) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		p.isSet = true
		return nil
	}

	var t []T
	if err := json.Unmarshal(data, &t); err != nil {
		return err
	}

	p.isSet = true
	p.value = t
	return nil
}

func (highOp sliceOperatorValue[T]) merge(lowOp sliceOperatorValue[T]) (sliceOperatorValue[T], error) {
	if !lowOp.isSet {
		return highOp, nil
	}

	if !highOp.isSet {
		return lowOp, nil
	}

	if !compareSlices(highOp.value, lowOp.value) {
		return sliceOperatorValue[T]{}, errors.New("operator 'value' was informed by both policies but the values are different")
	}

	return highOp, nil
}

func (op sliceOperatorValue[T]) apply(field []T) ([]T, error) {
	if !op.isSet {
		return field, nil
	}

	return op.value, nil
}

type sliceOperatorAdd[T any] []T

func (highOp sliceOperatorAdd[T]) merge(lowOp sliceOperatorAdd[T]) (sliceOperatorAdd[T], error) {
	if len(lowOp) == 0 {
		return highOp, nil
	}

	for _, value := range lowOp {
		if !deepContains(highOp, value) {
			highOp = append(highOp, value)
		}
	}

	return highOp, nil
}

func (op sliceOperatorAdd[T]) apply(field []T) ([]T, error) {
	for _, value := range op {
		if !deepContains(field, value) {
			field = append(field, value)
		}
	}

	return field, nil
}

type sliceOperatorDefault[T any] []T

func (highOp sliceOperatorDefault[T]) merge(lowOp sliceOperatorDefault[T]) (sliceOperatorDefault[T], error) {
	if len(lowOp) == 0 {
		return highOp, nil
	}

	if len(highOp) == 0 {
		return lowOp, nil
	}

	if !compareSlices(highOp, lowOp) {
		return sliceOperatorDefault[T]{}, errors.New("operator 'default' was informed by both policies but the values are different")
	}

	return highOp, nil
}

func (op sliceOperatorDefault[T]) apply(field []T) ([]T, error) {
	if len(op) == 0 {
		return field, nil
	}

	if len(field) == 0 {
		return op, nil
	}

	return field, nil
}

type sliceOperatorSubsetOf[T any] []T

func (highOp sliceOperatorSubsetOf[T]) merge(lowOp sliceOperatorSubsetOf[T]) (sliceOperatorSubsetOf[T], error) {
	if len(lowOp) == 0 {
		return highOp, nil
	}

	if len(highOp) == 0 {
		return lowOp, nil
	}

	var subsetOf []T
	for _, value := range lowOp {
		if deepContains(highOp, value) {
			subsetOf = append(subsetOf, value)
		}
	}

	if len(subsetOf) == 0 {
		return nil, errors.New("operator 'subsetOf' was informed by both policies but the values have no intersection")
	}

	return subsetOf, nil
}

func (op sliceOperatorSubsetOf[T]) apply(field []T) ([]T, error) {
	if len(op) == 0 {
		return field, nil
	}

	var subSet []T
	for _, e := range field {
		if deepContains(op, e) {
			subSet = append(subSet, e)
		}
	}

	return subSet, nil
}

type sliceOperatorSupersetOf[T any] []T

func (highOp sliceOperatorSupersetOf[T]) merge(lowOp sliceOperatorSupersetOf[T]) (sliceOperatorSupersetOf[T], error) {
	if len(lowOp) == 0 {
		return highOp, nil
	}

	for _, value := range lowOp {
		if !deepContains(highOp, value) {
			highOp = append(highOp, value)
		}
	}

	return highOp, nil
}

func (op sliceOperatorSupersetOf[T]) apply(field []T) ([]T, error) {
	if len(op) == 0 {
		return field, nil
	}

	for _, e := range op {
		if !deepContains(field, e) {
			return nil, fmt.Errorf("field %v is not a super set of %v", field, op)
		}
	}

	return field, nil
}

type primitiveOperatorEssential[T any] bool

func (highOp primitiveOperatorEssential[T]) merge(lowOp primitiveOperatorEssential[T]) (primitiveOperatorEssential[T], error) {
	return highOp || lowOp, nil
}

func (op primitiveOperatorEssential[T]) apply(field T) (T, error) {
	var zeroValue T
	isEssential := bool(op)
	if isEssential && reflect.DeepEqual(field, zeroValue) {
		return zeroValue, fmt.Errorf("field %v is essential by was not informed", field)
	}

	return field, nil
}

type sliceOperatorEssential[T any] bool

func (highOp sliceOperatorEssential[T]) merge(lowOp sliceOperatorEssential[T]) (sliceOperatorEssential[T], error) {
	return highOp || lowOp, nil
}

func (op sliceOperatorEssential[T]) apply(field []T) ([]T, error) {
	isEssential := bool(op)
	if isEssential && field == nil {
		return nil, fmt.Errorf("field %v is essential by was not informed", field)
	}

	return field, nil
}

func compareSlices[T any](x, y []T) bool {
	if len(x) != len(y) {
		return false
	}

	for _, e := range y {
		if !deepContains(x, e) {
			return false
		}
	}

	return true
}

func deepContains[T any](s []T, e T) bool {
	return slices.ContainsFunc(s, func(se T) bool {
		return reflect.DeepEqual(se, e)
	})
}
