package federation

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type testCaseInterface interface {
	runTest(t *testing.T)
}

func TestMetadataPolicyPrimitiveOps_Merge(t *testing.T) {

	// Given.
	highMetadataOps := metadataPolicyPrimitiveOps[int]{}
	lowMetadataOps := metadataPolicyPrimitiveOps[int]{}

	// When.
	got, err := highMetadataOps.merge(lowMetadataOps)

	// Then.

	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(
		got,
		highMetadataOps,
		cmp.AllowUnexported(primitiveOperatorValue[int]{}, primitiveOperatorDefault[int]{}),
	); diff != "" {
		t.Error(diff)
	}
}

func TestMetadataPolicyPrimitiveOps_Apply(t *testing.T) {

	// Given.
	ops := metadataPolicyPrimitiveOps[int]{}
	field := 1

	// When.
	got, err := ops.apply(field)

	// Then.

	if err != nil {
		t.Fatal(err)
	}

	if got != field {
		t.Errorf("got %d, want %d", got, field)
	}
}

func TestMetadataPolicySliceOps_Merge(t *testing.T) {

	// Given.
	highMetadataOps := metadataPolicySliceOps[int]{}
	lowMetadataOps := metadataPolicySliceOps[int]{}

	// When.
	got, err := highMetadataOps.merge(lowMetadataOps)

	// Then.

	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(
		got,
		highMetadataOps,
		cmp.AllowUnexported(sliceOperatorValue[int]{}),
	); diff != "" {
		t.Error(diff)
	}
}

func TestMetadataPolicySliceOps_Apply(t *testing.T) {

	// Given.
	ops := metadataPolicySliceOps[int]{}
	field := []int{1}

	// When.
	got, err := ops.apply(field)

	// Then.

	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(got, field); diff != "" {
		t.Error(diff)
	}
}

type testCasePrimitiveOperatorValueMerge[T comparable] struct {
	highOp  primitiveOperatorValue[T]
	lowOp   primitiveOperatorValue[T]
	want    primitiveOperatorValue[T]
	wantErr bool
}

func (testCase testCasePrimitiveOperatorValueMerge[T]) runTest(t *testing.T) {
	// When.
	got, err := testCase.highOp.merge(testCase.lowOp)

	// Then.
	if testCase.wantErr {
		if err == nil {
			t.Fatal("error is expected")
		}
		return
	}

	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(
		got,
		testCase.want,
		cmp.AllowUnexported(primitiveOperatorValue[T]{}),
	); diff != "" {
		t.Error(diff)
	}
}

func TestPrimitiveOperatorValue_Merge(t *testing.T) {

	// Given.
	testCases := []testCaseInterface{
		testCasePrimitiveOperatorValueMerge[int]{
			highOp: primitiveOperatorValue[int]{
				isSet: false,
			},
			lowOp: primitiveOperatorValue[int]{
				isSet: false,
			},
			want: primitiveOperatorValue[int]{
				isSet: false,
			},
		},
		testCasePrimitiveOperatorValueMerge[*int]{
			highOp: primitiveOperatorValue[*int]{
				isSet: true,
				value: nil,
			},
			lowOp: primitiveOperatorValue[*int]{
				isSet: false,
			},
			want: primitiveOperatorValue[*int]{
				isSet: true,
				value: nil,
			},
		},
		testCasePrimitiveOperatorValueMerge[int]{
			highOp: primitiveOperatorValue[int]{
				isSet: true,
				value: 1,
			},
			lowOp: primitiveOperatorValue[int]{
				isSet: false,
			},
			want: primitiveOperatorValue[int]{
				isSet: true,
				value: 1,
			},
		},
		testCasePrimitiveOperatorValueMerge[int]{
			highOp: primitiveOperatorValue[int]{
				isSet: false,
			},
			lowOp: primitiveOperatorValue[int]{
				isSet: true,
				value: 1,
			},
			want: primitiveOperatorValue[int]{
				isSet: true,
				value: 1,
			},
		},
		testCasePrimitiveOperatorValueMerge[int]{
			highOp: primitiveOperatorValue[int]{
				isSet: true,
				value: 1,
			},
			lowOp: primitiveOperatorValue[int]{
				isSet: true,
				value: 1,
			},
			want: primitiveOperatorValue[int]{
				isSet: true,
				value: 1,
			},
		},
		testCasePrimitiveOperatorValueMerge[string]{
			highOp: primitiveOperatorValue[string]{
				isSet: true,
				value: "test",
			},
			lowOp: primitiveOperatorValue[string]{
				isSet: true,
				value: "test",
			},
			want: primitiveOperatorValue[string]{
				isSet: true,
				value: "test",
			},
		},
		testCasePrimitiveOperatorValueMerge[int]{
			highOp: primitiveOperatorValue[int]{
				isSet: true,
				value: 1,
			},
			lowOp: primitiveOperatorValue[int]{
				isSet: true,
				value: 2,
			},
			wantErr: true,
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), testCase.runTest)
	}
}

type testCasePrimitiveOperatorValueApply[T comparable] struct {
	op      primitiveOperatorValue[T]
	field   T
	want    T
	wantErr bool
}

func (testCase testCasePrimitiveOperatorValueApply[T]) runTest(t *testing.T) {
	// When.
	got, err := testCase.op.apply(testCase.field)

	// Then.
	if testCase.wantErr {
		if err == nil {
			t.Fatal("error is expected")
		}
		return
	}

	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(got, testCase.want); diff != "" {
		t.Error(diff)
	}
}

func TestPrimitiveOperatorValue_Apply(t *testing.T) {
	// Given.
	testCases := []testCaseInterface{
		testCasePrimitiveOperatorValueApply[int]{
			op: primitiveOperatorValue[int]{
				isSet: false,
			},
			field: 1,
			want:  1,
		},
		testCasePrimitiveOperatorValueApply[string]{
			op: primitiveOperatorValue[string]{
				isSet: false,
			},
			field: "test",
			want:  "test",
		},
		testCasePrimitiveOperatorValueApply[int]{
			op: primitiveOperatorValue[int]{
				isSet: true,
				value: 1,
			},
			field: 2,
			want:  1,
		},
		testCasePrimitiveOperatorValueApply[string]{
			op: primitiveOperatorValue[string]{
				isSet: true,
				value: "test",
			},
			field: "random",
			want:  "test",
		},
		testCasePrimitiveOperatorValueApply[*int]{
			op: primitiveOperatorValue[*int]{
				isSet: true,
				value: nil,
			},
			field: pointerOf(1),
			want:  nil,
		},
		testCasePrimitiveOperatorValueApply[*string]{
			op: primitiveOperatorValue[*string]{
				isSet: true,
				value: nil,
			},
			field: pointerOf("test"),
			want:  nil,
		},
	}

	// When.
	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), testCase.runTest)
	}
}

type testCaseSliceOperatorValueMerge[T comparable] struct {
	highOp  sliceOperatorValue[T]
	lowOp   sliceOperatorValue[T]
	want    sliceOperatorValue[T]
	wantErr bool
}

func (testCase testCaseSliceOperatorValueMerge[T]) runTest(t *testing.T) {
	// When.
	got, err := testCase.highOp.merge(testCase.lowOp)

	// Then.
	if testCase.wantErr {
		if err == nil {
			t.Fatal("error is expected")
		}
		return
	}

	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(
		got,
		testCase.want,
		cmp.AllowUnexported(sliceOperatorValue[T]{}),
	); diff != "" {
		t.Error(diff)
	}
}

func TestSliceOperatorValue_Merge(t *testing.T) {

	// Given.
	testCases := []testCaseInterface{
		testCaseSliceOperatorValueMerge[int]{
			highOp: sliceOperatorValue[int]{
				isSet: false,
			},
			lowOp: sliceOperatorValue[int]{
				isSet: false,
			},
			want: sliceOperatorValue[int]{
				isSet: false,
			},
		},
		testCaseSliceOperatorValueMerge[*int]{
			highOp: sliceOperatorValue[*int]{
				isSet: true,
				value: nil,
			},
			lowOp: sliceOperatorValue[*int]{
				isSet: false,
			},
			want: sliceOperatorValue[*int]{
				isSet: true,
				value: nil,
			},
		},
		testCaseSliceOperatorValueMerge[int]{
			highOp: sliceOperatorValue[int]{
				isSet: true,
				value: []int{1},
			},
			lowOp: sliceOperatorValue[int]{
				isSet: false,
			},
			want: sliceOperatorValue[int]{
				isSet: true,
				value: []int{1},
			},
		},
		testCaseSliceOperatorValueMerge[int]{
			highOp: sliceOperatorValue[int]{
				isSet: false,
			},
			lowOp: sliceOperatorValue[int]{
				isSet: true,
				value: []int{1},
			},
			want: sliceOperatorValue[int]{
				isSet: true,
				value: []int{1},
			},
		},
		testCaseSliceOperatorValueMerge[int]{
			highOp: sliceOperatorValue[int]{
				isSet: true,
				value: []int{1},
			},
			lowOp: sliceOperatorValue[int]{
				isSet: true,
				value: []int{1},
			},
			want: sliceOperatorValue[int]{
				isSet: true,
				value: []int{1},
			},
		},
		testCaseSliceOperatorValueMerge[string]{
			highOp: sliceOperatorValue[string]{
				isSet: true,
				value: []string{"test"},
			},
			lowOp: sliceOperatorValue[string]{
				isSet: true,
				value: []string{"test"},
			},
			want: sliceOperatorValue[string]{
				isSet: true,
				value: []string{"test"},
			},
		},
		testCaseSliceOperatorValueMerge[goidc.SignatureAlgorithm]{
			highOp: sliceOperatorValue[goidc.SignatureAlgorithm]{
				isSet: true,
				value: []goidc.SignatureAlgorithm{"test1", "test2"},
			},
			lowOp: sliceOperatorValue[goidc.SignatureAlgorithm]{
				isSet: true,
				value: []goidc.SignatureAlgorithm{"test2", "test1"},
			},
			want: sliceOperatorValue[goidc.SignatureAlgorithm]{
				isSet: true,
				value: []goidc.SignatureAlgorithm{"test1", "test2"},
			},
		},
		testCaseSliceOperatorValueMerge[int]{
			highOp: sliceOperatorValue[int]{
				isSet: true,
				value: []int{1},
			},
			lowOp: sliceOperatorValue[int]{
				isSet: true,
				value: []int{2},
			},
			wantErr: true,
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), testCase.runTest)
	}
}

type testCaseSliceOperatorValueApply[T comparable] struct {
	op      sliceOperatorValue[T]
	field   []T
	want    []T
	wantErr bool
}

func (testCase testCaseSliceOperatorValueApply[T]) runTest(t *testing.T) {
	// When.
	got, err := testCase.op.apply(testCase.field)

	// Then.
	if testCase.wantErr {
		if err == nil {
			t.Fatal("error is expected")
		}
		return
	}

	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(got, testCase.want); diff != "" {
		t.Error(diff)
	}
}

func TestSliceOperatorValue_Apply(t *testing.T) {
	// Given.
	testCases := []testCaseInterface{
		testCaseSliceOperatorValueApply[int]{
			op: sliceOperatorValue[int]{
				isSet: false,
			},
			field: []int{1},
			want:  []int{1},
		},
		testCaseSliceOperatorValueApply[string]{
			op: sliceOperatorValue[string]{
				isSet: false,
			},
			field: []string{"test"},
			want:  []string{"test"},
		},
		testCaseSliceOperatorValueApply[int]{
			op: sliceOperatorValue[int]{
				isSet: true,
				value: []int{1},
			},
			field: []int{2},
			want:  []int{1},
		},
		testCaseSliceOperatorValueApply[string]{
			op: sliceOperatorValue[string]{
				isSet: true,
				value: []string{"test"},
			},
			field: []string{"random"},
			want:  []string{"test"},
		},
		testCaseSliceOperatorValueApply[int]{
			op: sliceOperatorValue[int]{
				isSet: true,
				value: nil,
			},
			field: []int{1},
			want:  nil,
		},
	}

	// When.
	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), testCase.runTest)
	}
}

type testCaseSliceOperatorAddMerge[T comparable] struct {
	highOp  sliceOperatorAdd[T]
	lowOp   sliceOperatorAdd[T]
	want    sliceOperatorAdd[T]
	wantErr bool
}

func (testCase testCaseSliceOperatorAddMerge[T]) runTest(t *testing.T) {
	// When.
	got, err := testCase.highOp.merge(testCase.lowOp)

	// Then.
	if testCase.wantErr {
		if err == nil {
			t.Fatal("error is expected")
		}
		return
	}

	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(got, testCase.want); diff != "" {
		t.Error(diff)
	}
}

func TestSliceOperatorAdd_Merge(t *testing.T) {
	// Given.
	testCases := []testCaseInterface{
		testCaseSliceOperatorAddMerge[int]{
			highOp: nil,
			lowOp:  nil,
			want:   nil,
		},
		testCaseSliceOperatorAddMerge[string]{
			highOp: []string{"test1"},
			lowOp:  nil,
			want:   []string{"test1"},
		},
		testCaseSliceOperatorAddMerge[string]{
			highOp: nil,
			lowOp:  []string{"test1"},
			want:   []string{"test1"},
		},
		testCaseSliceOperatorAddMerge[string]{
			highOp: []string{"test1"},
			lowOp:  []string{"test2"},
			want:   []string{"test1", "test2"},
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), testCase.runTest)
	}
}

type testCaseSliceOperatorAddApply[T comparable] struct {
	op      sliceOperatorAdd[T]
	field   []T
	want    []T
	wantErr bool
}

func (testCase testCaseSliceOperatorAddApply[T]) runTest(t *testing.T) {
	// When.
	got, err := testCase.op.apply(testCase.field)

	// Then.
	if testCase.wantErr {
		if err == nil {
			t.Fatal("error is expected")
		}
		return
	}

	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(got, testCase.want); diff != "" {
		t.Error(diff)
	}
}

func TestSliceOperatorAdd_Apply(t *testing.T) {
	// Given.
	testCases := []testCaseInterface{
		testCaseSliceOperatorAddApply[int]{
			op:    nil,
			field: []int{1},
			want:  []int{1},
		},
		testCaseSliceOperatorAddApply[int]{
			op:    nil,
			field: []int{1},
			want:  []int{1},
		},
		testCaseSliceOperatorAddApply[int]{
			op:    []int{1},
			field: []int{1},
			want:  []int{1},
		},
		testCaseSliceOperatorAddApply[int]{
			op:    []int{1, 2},
			field: []int{1},
			want:  []int{1, 2},
		},
		testCaseSliceOperatorAddApply[int]{
			op:    []int{1},
			field: []int{1, 3},
			want:  []int{1, 3},
		},
		testCaseSliceOperatorAddApply[string]{
			op:    []string{"test"},
			field: []string{"test"},
			want:  []string{"test"},
		},
	}

	// When.
	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), testCase.runTest)
	}
}

type testCasePrimitiveOperatorDefaultMerge[T comparable] struct {
	highOp  primitiveOperatorDefault[T]
	lowOp   primitiveOperatorDefault[T]
	want    primitiveOperatorDefault[T]
	wantErr bool
}

func (testCase testCasePrimitiveOperatorDefaultMerge[T]) runTest(t *testing.T) {
	// When.
	got, err := testCase.highOp.merge(testCase.lowOp)

	// Then.
	if testCase.wantErr {
		if err == nil {
			t.Fatal("error is expected")
		}
		return
	}

	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(
		got,
		testCase.want,
		cmp.AllowUnexported(primitiveOperatorDefault[T]{}),
	); diff != "" {
		t.Error(diff)
	}
}

func TestPrimitiveOperatorDefault_Merge(t *testing.T) {
	// Given.
	testCases := []testCaseInterface{
		testCasePrimitiveOperatorDefaultMerge[int]{
			highOp: primitiveOperatorDefault[int]{
				value: 0,
			},
			lowOp: primitiveOperatorDefault[int]{
				value: 0,
			},
			want: primitiveOperatorDefault[int]{
				value: 0,
			},
		},
		testCasePrimitiveOperatorDefaultMerge[int]{
			highOp: primitiveOperatorDefault[int]{
				value: 1,
			},
			lowOp: primitiveOperatorDefault[int]{
				value: 0,
			},
			want: primitiveOperatorDefault[int]{
				value: 1,
			},
		},
		testCasePrimitiveOperatorDefaultMerge[int]{
			highOp: primitiveOperatorDefault[int]{
				value: 0,
			},
			lowOp: primitiveOperatorDefault[int]{
				value: 1,
			},
			want: primitiveOperatorDefault[int]{
				value: 1,
			},
		},
		testCasePrimitiveOperatorDefaultMerge[int]{
			highOp: primitiveOperatorDefault[int]{
				value: 1,
			},
			lowOp: primitiveOperatorDefault[int]{
				value: 1,
			},
			want: primitiveOperatorDefault[int]{
				value: 1,
			},
		},
		testCasePrimitiveOperatorDefaultMerge[*int]{
			highOp: primitiveOperatorDefault[*int]{
				value: pointerOf(1),
			},
			lowOp: primitiveOperatorDefault[*int]{
				value: pointerOf(1),
			},
			want: primitiveOperatorDefault[*int]{
				value: pointerOf(1),
			},
		},
		testCasePrimitiveOperatorDefaultMerge[int]{
			highOp: primitiveOperatorDefault[int]{
				value: 1,
			},
			lowOp: primitiveOperatorDefault[int]{
				value: 2,
			},
			wantErr: true,
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), testCase.runTest)
	}
}

type testCasePrimitiveOperatorDefaultApply[T comparable] struct {
	op      primitiveOperatorDefault[T]
	field   T
	want    T
	wantErr bool
}

func (testCase testCasePrimitiveOperatorDefaultApply[T]) runTest(t *testing.T) {
	// When.
	got, err := testCase.op.apply(testCase.field)

	// Then.
	if testCase.wantErr {
		if err == nil {
			t.Fatal("error is expected")
		}
		return
	}

	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(got, testCase.want); diff != "" {
		t.Error(diff)
	}
}

func TestPrimitiveOperatorDefault_Apply(t *testing.T) {
	// Given.
	testCases := []testCaseInterface{
		testCasePrimitiveOperatorDefaultApply[int]{
			op: primitiveOperatorDefault[int]{
				value: 0,
			},
			field: 0,
			want:  0,
		},
		testCasePrimitiveOperatorDefaultApply[int]{
			op: primitiveOperatorDefault[int]{
				value: 0,
			},
			field: 1,
			want:  1,
		},
		testCasePrimitiveOperatorDefaultApply[string]{
			op: primitiveOperatorDefault[string]{
				value: "",
			},
			field: "test",
			want:  "test",
		},
		testCasePrimitiveOperatorDefaultApply[int]{
			op: primitiveOperatorDefault[int]{
				value: 1,
			},
			field: 0,
			want:  1,
		},
		testCasePrimitiveOperatorDefaultApply[*int]{
			op: primitiveOperatorDefault[*int]{
				value: pointerOf(1),
			},
			field: pointerOf(1),
			want:  pointerOf(1),
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), testCase.runTest)
	}
}

type testCaseSliceOperatorDefaultMerge[T comparable] struct {
	highOp  sliceOperatorDefault[T]
	lowOp   sliceOperatorDefault[T]
	want    sliceOperatorDefault[T]
	wantErr bool
}

func (testCase testCaseSliceOperatorDefaultMerge[T]) runTest(t *testing.T) {
	// When.
	got, err := testCase.highOp.merge(testCase.lowOp)

	// Then.
	if testCase.wantErr {
		if err == nil {
			t.Fatal("error is expected")
		}
		return
	}

	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(got, testCase.want); diff != "" {
		t.Error(diff)
	}
}

func TestSliceOperatorDefault_Merge(t *testing.T) {
	// Given.
	testCases := []testCaseInterface{
		testCaseSliceOperatorDefaultMerge[int]{
			highOp: nil,
			lowOp:  nil,
			want:   nil,
		},
		testCaseSliceOperatorDefaultMerge[int]{
			highOp: nil,
			lowOp:  []int{1},
			want:   []int{1},
		},
		testCaseSliceOperatorDefaultMerge[int]{
			highOp: []int{1},
			lowOp:  nil,
			want:   []int{1},
		},
		testCaseSliceOperatorDefaultMerge[int]{
			highOp: []int{1},
			lowOp:  []int{1},
			want:   []int{1},
		},
		testCaseSliceOperatorDefaultMerge[*int]{
			highOp: []*int{pointerOf(1)},
			lowOp:  []*int{pointerOf(1)},
			want:   []*int{pointerOf(1)},
		},
		testCaseSliceOperatorDefaultMerge[int]{
			highOp:  []int{1},
			lowOp:   []int{2},
			wantErr: true,
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), testCase.runTest)
	}
}

type testCaseSliceOperatorDefaultApply[T comparable] struct {
	op      sliceOperatorDefault[T]
	field   []T
	want    []T
	wantErr bool
}

func (testCase testCaseSliceOperatorDefaultApply[T]) runTest(t *testing.T) {
	// When.
	got, err := testCase.op.apply(testCase.field)

	// Then.
	if testCase.wantErr {
		if err == nil {
			t.Fatal("error is expected")
		}
		return
	}

	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(got, testCase.want); diff != "" {
		t.Error(diff)
	}
}

func TestSliceOperatorDefault_Apply(t *testing.T) {
	// Given.
	testCases := []testCaseInterface{
		testCaseSliceOperatorDefaultApply[int]{
			op:    nil,
			field: []int{1},
			want:  []int{1},
		},
		testCaseSliceOperatorDefaultApply[int]{
			op:    nil,
			field: nil,
			want:  nil,
		},
		testCaseSliceOperatorDefaultApply[string]{
			op:    []string{"test1"},
			field: []string{"test"},
			want:  []string{"test"},
		},
		testCaseSliceOperatorDefaultApply[int]{
			op:    []int{1},
			field: nil,
			want:  []int{1},
		},
		testCaseSliceOperatorDefaultApply[*int]{
			op:    []*int{pointerOf(1)},
			field: []*int{pointerOf(1)},
			want:  []*int{pointerOf(1)},
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), testCase.runTest)
	}
}

type testCasePrimitiveOperatorOneOfMerge[T comparable] struct {
	highOp  primitiveOperatorOneOf[T]
	lowOp   primitiveOperatorOneOf[T]
	want    primitiveOperatorOneOf[T]
	wantErr bool
}

func (testCase testCasePrimitiveOperatorOneOfMerge[T]) runTest(t *testing.T) {
	// When.
	got, err := testCase.highOp.merge(testCase.lowOp)

	// Then.
	if testCase.wantErr {
		if err == nil {
			t.Fatal("error is expected")
		}
		return
	}

	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(got, testCase.want); diff != "" {
		t.Error(diff)
	}
}

func TestPrimitiveOperatorOneOf_Merge(t *testing.T) {
	// Given.
	testCases := []testCaseInterface{
		testCasePrimitiveOperatorOneOfMerge[int]{
			highOp: nil,
			lowOp:  nil,
			want:   nil,
		},
		testCasePrimitiveOperatorOneOfMerge[int]{
			highOp: []int{1},
			lowOp:  nil,
			want:   []int{1},
		},
		testCasePrimitiveOperatorOneOfMerge[int]{
			highOp: nil,
			lowOp:  []int{1},
			want:   []int{1},
		},
		testCasePrimitiveOperatorOneOfMerge[int]{
			highOp: []int{1, 2},
			lowOp:  []int{2, 3},
			want:   []int{2},
		},
		testCasePrimitiveOperatorOneOfMerge[int]{
			highOp:  []int{1, 2},
			lowOp:   []int{3},
			wantErr: true,
		},
	}

	// When.
	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), testCase.runTest)
	}
}

type testCasePrimitiveOperatorOneOfApply[T comparable] struct {
	op      primitiveOperatorOneOf[T]
	field   T
	want    T
	wantErr bool
}

func (testCase testCasePrimitiveOperatorOneOfApply[T]) runTest(t *testing.T) {
	// When.
	got, err := testCase.op.apply(testCase.field)

	// Then.
	if testCase.wantErr {
		if err == nil {
			t.Fatal("error is expected")
		}
		return
	}

	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(got, testCase.want); diff != "" {
		t.Error(diff)
	}
}

func TestPrimitiveOperatorOneOf_Apply(t *testing.T) {
	// Given.
	testCases := []testCaseInterface{
		testCasePrimitiveOperatorOneOfApply[int]{
			op:    nil,
			field: 0,
			want:  0,
		},
		testCasePrimitiveOperatorOneOfApply[int]{
			op:    nil,
			field: 1,
			want:  1,
		},
		testCasePrimitiveOperatorOneOfApply[string]{
			op:    nil,
			field: "test",
			want:  "test",
		},
		testCasePrimitiveOperatorOneOfApply[int]{
			op:    []int{0, 1},
			field: 1,
			want:  1,
		},
		testCasePrimitiveOperatorOneOfApply[int]{
			op:      []int{0, 1},
			field:   2,
			wantErr: true,
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), testCase.runTest)
	}
}

type testCaseSliceOperatorSubsetOfMerge[T comparable] struct {
	highOp  sliceOperatorSubsetOf[T]
	lowOp   sliceOperatorSubsetOf[T]
	want    sliceOperatorSubsetOf[T]
	wantErr bool
}

func (testCase testCaseSliceOperatorSubsetOfMerge[T]) runTest(t *testing.T) {
	// When.
	got, err := testCase.highOp.merge(testCase.lowOp)

	// Then.
	if testCase.wantErr {
		if err == nil {
			t.Fatal("error is expected")
		}
		return
	}

	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(got, testCase.want); diff != "" {
		t.Error(diff)
	}
}

func TestSliceOperatorSubsetOf_Merge(t *testing.T) {
	// Given.
	testCases := []testCaseInterface{
		testCaseSliceOperatorSubsetOfMerge[int]{
			highOp: nil,
			lowOp:  nil,
			want:   nil,
		},
		testCaseSliceOperatorSubsetOfMerge[int]{
			highOp: []int{1},
			lowOp:  nil,
			want:   []int{1},
		},
		testCaseSliceOperatorSubsetOfMerge[int]{
			highOp: nil,
			lowOp:  []int{1},
			want:   []int{1},
		},
		testCaseSliceOperatorSubsetOfMerge[int]{
			highOp: []int{1, 2},
			lowOp:  []int{2, 3},
			want:   []int{2},
		},
		testCaseSliceOperatorSubsetOfMerge[int]{
			highOp:  []int{1, 2},
			lowOp:   []int{3},
			wantErr: true,
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), testCase.runTest)
	}
}

type testCaseSliceOperatorSubsetOfApply[T comparable] struct {
	op      sliceOperatorSubsetOf[T]
	field   []T
	want    []T
	wantErr bool
}

func (testCase testCaseSliceOperatorSubsetOfApply[T]) runTest(t *testing.T) {
	// When.
	got, err := testCase.op.apply(testCase.field)

	// Then.
	if testCase.wantErr {
		if err == nil {
			t.Fatal("error is expected")
		}
		return
	}

	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(got, testCase.want); diff != "" {
		t.Error(diff)
	}
}

func TestSliceOperatorSubsetOf_Apply(t *testing.T) {
	// Given.
	testCases := []testCaseInterface{
		testCaseSliceOperatorSubsetOfApply[int]{
			op:    nil,
			field: nil,
			want:  nil,
		},
		testCaseSliceOperatorSubsetOfApply[int]{
			op:    nil,
			field: []int{1},
			want:  []int{1},
		},
		testCaseSliceOperatorSubsetOfApply[int]{
			op:    []int{1, 2, 3},
			field: []int{1, 2},
			want:  []int{1, 2},
		},
		testCaseSliceOperatorSubsetOfApply[int]{
			op:    []int{1, 2},
			field: []int{3},
			want:  nil,
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), testCase.runTest)
	}
}

type testCaseSliceOperatorSupersetOfMerge[T comparable] struct {
	highOp  sliceOperatorSupersetOf[T]
	lowOp   sliceOperatorSupersetOf[T]
	want    sliceOperatorSupersetOf[T]
	wantErr bool
}

func (testCase testCaseSliceOperatorSupersetOfMerge[T]) runTest(t *testing.T) {
	// When.
	got, err := testCase.highOp.merge(testCase.lowOp)

	// Then.
	if testCase.wantErr {
		if err == nil {
			t.Fatal("error is expected")
		}
		return
	}

	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(got, testCase.want); diff != "" {
		t.Error(diff)
	}
}

func TestOperatorSupersetOf_Merge(t *testing.T) {
	// Given.
	testCases := []testCaseInterface{
		testCaseSliceOperatorSupersetOfMerge[int]{
			highOp: nil,
			lowOp:  nil,
			want:   nil,
		},
		testCaseSliceOperatorSupersetOfMerge[string]{
			highOp: []string{"test1"},
			lowOp:  nil,
			want:   []string{"test1"},
		},
		testCaseSliceOperatorSupersetOfMerge[string]{
			highOp: nil,
			lowOp:  []string{"test1"},
			want:   []string{"test1"},
		},
		testCaseSliceOperatorSupersetOfMerge[string]{
			highOp: []string{"test1"},
			lowOp:  []string{"test2"},
			want:   []string{"test1", "test2"},
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), testCase.runTest)
	}
}

type testCaseSliceOperatorSupersetOfApply[T comparable] struct {
	op      sliceOperatorSupersetOf[T]
	field   []T
	want    []T
	wantErr bool
}

func (testCase testCaseSliceOperatorSupersetOfApply[T]) runTest(t *testing.T) {
	// When.
	got, err := testCase.op.apply(testCase.field)

	// Then.
	if testCase.wantErr {
		if err == nil {
			t.Fatal("error is expected")
		}
		return
	}

	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(got, testCase.want); diff != "" {
		t.Error(diff)
	}
}

func TestSliceOperatorSupersetOf_Apply(t *testing.T) {
	// Given.
	testCases := []testCaseInterface{
		testCaseSliceOperatorSupersetOfApply[int]{
			op:    nil,
			field: nil,
			want:  nil,
		},
		testCaseSliceOperatorSupersetOfApply[int]{
			op:    nil,
			field: []int{1},
			want:  []int{1},
		},
		testCaseSliceOperatorSupersetOfApply[int]{
			op:    []int{1, 2, 3},
			field: []int{1, 2, 3},
			want:  []int{1, 2, 3},
		},
		testCaseSliceOperatorSupersetOfApply[int]{
			op:      []int{1, 2},
			field:   []int{3},
			wantErr: true,
		},
		testCaseSliceOperatorSupersetOfApply[int]{
			op:      []int{1},
			field:   nil,
			wantErr: true,
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), testCase.runTest)
	}
}

type testCasePrimitiveOperatorEssentialMerge[T comparable] struct {
	highOp primitiveOperatorEssential[T]
	lowOp  primitiveOperatorEssential[T]
	want   primitiveOperatorEssential[T]
}

func (testCase testCasePrimitiveOperatorEssentialMerge[T]) runTest(t *testing.T) {
	// When.
	got, err := testCase.highOp.merge(testCase.lowOp)

	// Then.
	if err != nil {
		t.Fatal(err)
	}

	if got != testCase.want {
		t.Errorf("got %t, want %t", got, testCase.want)
	}
}

func TestPrimitiveOperatorEssential_Merge(t *testing.T) {
	// Given.
	testCases := []testCaseInterface{
		testCasePrimitiveOperatorEssentialMerge[int]{
			highOp: false,
			lowOp:  false,
			want:   false,
		},
		testCasePrimitiveOperatorEssentialMerge[int]{
			highOp: false,
			lowOp:  true,
			want:   true,
		},
		testCasePrimitiveOperatorEssentialMerge[int]{
			highOp: true,
			lowOp:  false,
			want:   true,
		},
		testCasePrimitiveOperatorEssentialMerge[int]{
			highOp: true,
			lowOp:  true,
			want:   true,
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), testCase.runTest)
	}
}

type testCasePrimitiveOperatorEssentialApply[T comparable] struct {
	op      primitiveOperatorEssential[T]
	field   T
	want    T
	wantErr bool
}

func (testCase testCasePrimitiveOperatorEssentialApply[T]) runTest(t *testing.T) {
	// When.
	got, err := testCase.op.apply(testCase.field)

	// Then.
	if testCase.wantErr {
		if err == nil {
			t.Fatal("error is expected")
		}
		return
	}

	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(got, testCase.want); diff != "" {
		t.Error(diff)
	}
}

func TestPrimitiveOperatorEssential_Apply(t *testing.T) {
	// Given.
	testCases := []testCaseInterface{
		testCasePrimitiveOperatorEssentialApply[int]{
			op:    false,
			field: 1,
			want:  1,
		},
		testCasePrimitiveOperatorEssentialApply[int]{
			op:    false,
			field: 0,
			want:  0,
		},
		testCasePrimitiveOperatorEssentialApply[int]{
			op:    true,
			field: 1,
			want:  1,
		},
		testCasePrimitiveOperatorEssentialApply[*int]{
			op:    true,
			field: pointerOf(1),
			want:  pointerOf(1),
		},
		testCasePrimitiveOperatorEssentialApply[int]{
			op:      true,
			field:   0,
			wantErr: true,
		},
		testCasePrimitiveOperatorEssentialApply[*int]{
			op:      true,
			field:   nil,
			wantErr: true,
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), testCase.runTest)
	}
}

type testCaseSliceOperatorEssentialMerge[T comparable] struct {
	highOp sliceOperatorEssential[T]
	lowOp  sliceOperatorEssential[T]
	want   sliceOperatorEssential[T]
}

func (testCase testCaseSliceOperatorEssentialMerge[T]) runTest(t *testing.T) {
	// When.
	got, err := testCase.highOp.merge(testCase.lowOp)

	// Then.
	if err != nil {
		t.Fatal(err)
	}

	if got != testCase.want {
		t.Errorf("got %t, want %t", got, testCase.want)
	}
}

func TestSliceOperatorEssential_Merge(t *testing.T) {
	// Given.
	testCases := []testCaseInterface{
		testCaseSliceOperatorEssentialMerge[int]{
			highOp: false,
			lowOp:  false,
			want:   false,
		},
		testCaseSliceOperatorEssentialMerge[int]{
			highOp: false,
			lowOp:  true,
			want:   true,
		},
		testCaseSliceOperatorEssentialMerge[int]{
			highOp: true,
			lowOp:  false,
			want:   true,
		},
		testCaseSliceOperatorEssentialMerge[int]{
			highOp: true,
			lowOp:  true,
			want:   true,
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), testCase.runTest)
	}
}

type testCaseSliceOperatorEssentialApply[T comparable] struct {
	op      sliceOperatorEssential[T]
	field   []T
	want    []T
	wantErr bool
}

func (testCase testCaseSliceOperatorEssentialApply[T]) runTest(t *testing.T) {
	// When.
	got, err := testCase.op.apply(testCase.field)

	// Then.
	if testCase.wantErr {
		if err == nil {
			t.Fatal("error is expected")
		}
		return
	}

	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(got, testCase.want); diff != "" {
		t.Error(diff)
	}
}

func TestSliceOperatorEssential_Apply(t *testing.T) {
	// Given.
	testCases := []testCaseInterface{
		testCaseSliceOperatorEssentialApply[int]{
			op:    false,
			field: []int{1},
			want:  []int{1},
		},
		testCaseSliceOperatorEssentialApply[int]{
			op:    false,
			field: nil,
			want:  nil,
		},
		testCaseSliceOperatorEssentialApply[int]{
			op:    true,
			field: []int{1},
			want:  []int{1},
		},
		testCaseSliceOperatorEssentialApply[*int]{
			op:    true,
			field: []*int{pointerOf(1)},
			want:  []*int{pointerOf(1)},
		},
		testCaseSliceOperatorEssentialApply[int]{
			op:      true,
			field:   nil,
			wantErr: true,
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), testCase.runTest)
	}
}

func pointerOf[T any](t T) *T {
	return &t
}
