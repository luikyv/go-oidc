package federation

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestMetadataOperators_Merge(t *testing.T) {

	// Given.
	testCases := []testCaseInterface{
		testCaseMetadataOperatorsMerge[int]{
			highOps: metadataOperators[int]{
				Value: nullable[int]{
					Set: false,
				},
			},
			lowOps: metadataOperators[int]{
				Value: nullable[int]{
					Set: false,
				},
			},
			want: metadataOperators[int]{
				Value: nullable[int]{
					Set: false,
				},
			},
		},
		testCaseMetadataOperatorsMerge[*int]{
			highOps: metadataOperators[*int]{
				Value: nullable[*int]{
					Set:   true,
					Value: nil,
				},
			},
			lowOps: metadataOperators[*int]{
				Value: nullable[*int]{
					Set:   false,
					Value: nil,
				},
			},
			want: metadataOperators[*int]{
				Value: nullable[*int]{
					Set:   true,
					Value: nil,
				},
			},
		},
		testCaseMetadataOperatorsMerge[int]{
			highOps: metadataOperators[int]{
				Value: nullable[int]{
					Set:   true,
					Value: 1,
				},
			},
			lowOps: metadataOperators[int]{
				Value: nullable[int]{
					Set: false,
				},
			},
			want: metadataOperators[int]{
				Value: nullable[int]{
					Set:   true,
					Value: 1,
				},
			},
		},
		testCaseMetadataOperatorsMerge[int]{
			highOps: metadataOperators[int]{
				Value: nullable[int]{
					Set: false,
				},
			},
			lowOps: metadataOperators[int]{
				Value: nullable[int]{
					Set:   true,
					Value: 1,
				},
			},
			want: metadataOperators[int]{
				Value: nullable[int]{
					Set:   true,
					Value: 1,
				},
			},
		},
		testCaseMetadataOperatorsMerge[int]{
			highOps: metadataOperators[int]{
				Value: nullable[int]{
					Set:   true,
					Value: 1,
				},
			},
			lowOps: metadataOperators[int]{
				Value: nullable[int]{
					Set:   true,
					Value: 1,
				},
			},
			want: metadataOperators[int]{
				Value: nullable[int]{
					Set:   true,
					Value: 1,
				},
			},
		},
		testCaseMetadataOperatorsMerge[string]{
			highOps: metadataOperators[string]{
				Value: nullable[string]{
					Set:   true,
					Value: "test",
				},
			},
			lowOps: metadataOperators[string]{
				Value: nullable[string]{
					Set:   true,
					Value: "test",
				},
			},
			want: metadataOperators[string]{
				Value: nullable[string]{
					Set:   true,
					Value: "test",
				},
			},
		},
		testCaseMetadataOperatorsMerge[int]{
			highOps: metadataOperators[int]{
				Value: nullable[int]{
					Set:   true,
					Value: 1,
				},
			},
			lowOps: metadataOperators[int]{
				Value: nullable[int]{
					Set:   true,
					Value: 2,
				},
			},
			wantErr: true,
		},
		testCaseMetadataOperatorsMerge[[]int]{
			highOps: metadataOperators[[]int]{
				Value: nullable[[]int]{
					Set: false,
				},
			},
			lowOps: metadataOperators[[]int]{
				Value: nullable[[]int]{
					Set: false,
				},
			},
			want: metadataOperators[[]int]{
				Value: nullable[[]int]{
					Set: false,
				},
			},
		},
		testCaseMetadataOperatorsMerge[[]*int]{
			highOps: metadataOperators[[]*int]{
				Value: nullable[[]*int]{
					Set:   true,
					Value: nil,
				},
			},
			lowOps: metadataOperators[[]*int]{
				Value: nullable[[]*int]{
					Set: false,
				},
			},
			want: metadataOperators[[]*int]{
				Value: nullable[[]*int]{
					Set:   true,
					Value: nil,
				},
			},
		},
		testCaseMetadataOperatorsMerge[[]int]{
			highOps: metadataOperators[[]int]{
				Value: nullable[[]int]{
					Set:   true,
					Value: []int{1},
				},
			},
			lowOps: metadataOperators[[]int]{
				Value: nullable[[]int]{
					Set: false,
				},
			},
			want: metadataOperators[[]int]{
				Value: nullable[[]int]{
					Set:   true,
					Value: []int{1},
				},
			},
		},
		testCaseMetadataOperatorsMerge[[]int]{
			highOps: metadataOperators[[]int]{
				Value: nullable[[]int]{
					Set: false,
				},
			},
			lowOps: metadataOperators[[]int]{
				Value: nullable[[]int]{
					Set:   true,
					Value: []int{1},
				},
			},
			want: metadataOperators[[]int]{
				Value: nullable[[]int]{
					Set:   true,
					Value: []int{1},
				},
			},
		},
		testCaseMetadataOperatorsMerge[[]int]{
			highOps: metadataOperators[[]int]{
				Value: nullable[[]int]{
					Set:   true,
					Value: []int{1},
				},
			},
			lowOps: metadataOperators[[]int]{
				Value: nullable[[]int]{
					Set:   true,
					Value: []int{1},
				},
			},
			want: metadataOperators[[]int]{
				Value: nullable[[]int]{
					Set:   true,
					Value: []int{1},
				},
			},
		},
		testCaseMetadataOperatorsMerge[[]string]{
			highOps: metadataOperators[[]string]{
				Value: nullable[[]string]{
					Set:   true,
					Value: []string{"test"},
				},
			},
			lowOps: metadataOperators[[]string]{
				Value: nullable[[]string]{
					Set:   true,
					Value: []string{"test"},
				},
			},
			want: metadataOperators[[]string]{
				Value: nullable[[]string]{
					Set:   true,
					Value: []string{"test"},
				},
			},
		},
		testCaseMetadataOperatorsMerge[[]goidc.SignatureAlgorithm]{
			highOps: metadataOperators[[]goidc.SignatureAlgorithm]{
				Value: nullable[[]goidc.SignatureAlgorithm]{
					Set:   true,
					Value: []goidc.SignatureAlgorithm{"test1", "test2"},
				},
			},
			lowOps: metadataOperators[[]goidc.SignatureAlgorithm]{
				Value: nullable[[]goidc.SignatureAlgorithm]{
					Set:   true,
					Value: []goidc.SignatureAlgorithm{"test2", "test1"},
				},
			},
			want: metadataOperators[[]goidc.SignatureAlgorithm]{
				Value: nullable[[]goidc.SignatureAlgorithm]{
					Set:   true,
					Value: []goidc.SignatureAlgorithm{"test1", "test2"},
				},
			},
		},
		testCaseMetadataOperatorsMerge[[]int]{
			highOps: metadataOperators[[]int]{
				Value: nullable[[]int]{
					Set:   true,
					Value: []int{1},
				},
			},
			lowOps: metadataOperators[[]int]{
				Value: nullable[[]int]{
					Set:   true,
					Value: []int{2},
				},
			},
			wantErr: true,
		},
		testCaseMetadataOperatorsMerge[[]int]{
			highOps: metadataOperators[[]int]{
				Add: nil,
			},
			lowOps: metadataOperators[[]int]{
				Add: nil,
			},
			want: metadataOperators[[]int]{
				Add: nil,
			},
		},
		testCaseMetadataOperatorsMerge[[]string]{
			highOps: metadataOperators[[]string]{
				Add: []string{"test1"},
			},
			lowOps: metadataOperators[[]string]{
				Add: nil,
			},
			want: metadataOperators[[]string]{
				Add: []string{"test1"},
			},
		},
		testCaseMetadataOperatorsMerge[[]string]{
			highOps: metadataOperators[[]string]{
				Add: nil,
			},
			lowOps: metadataOperators[[]string]{
				Add: []string{"test1"},
			},
			want: metadataOperators[[]string]{
				Add: []string{"test1"},
			},
		},
		testCaseMetadataOperatorsMerge[[]string]{
			highOps: metadataOperators[[]string]{
				Add: []string{"test1"},
			},
			lowOps: metadataOperators[[]string]{
				Add: []string{"test2"},
			},
			want: metadataOperators[[]string]{
				Add: []string{"test1", "test2"},
			},
		},
		testCaseMetadataOperatorsMerge[int]{
			highOps: metadataOperators[int]{
				Default: 0,
			},
			lowOps: metadataOperators[int]{
				Default: 0,
			},
			want: metadataOperators[int]{
				Default: 0,
			},
		},
		testCaseMetadataOperatorsMerge[int]{
			highOps: metadataOperators[int]{
				Default: 1,
			},
			lowOps: metadataOperators[int]{
				Default: 0,
			},
			want: metadataOperators[int]{
				Default: 1,
			},
		},
		testCaseMetadataOperatorsMerge[int]{
			highOps: metadataOperators[int]{
				Default: 0,
			},
			lowOps: metadataOperators[int]{
				Default: 1,
			},
			want: metadataOperators[int]{
				Default: 1,
			},
		},
		testCaseMetadataOperatorsMerge[int]{
			highOps: metadataOperators[int]{
				Default: 1,
			},
			lowOps: metadataOperators[int]{
				Default: 1,
			},
			want: metadataOperators[int]{
				Default: 1,
			},
		},
		testCaseMetadataOperatorsMerge[*int]{
			highOps: metadataOperators[*int]{
				Default: pointerOf(1),
			},
			lowOps: metadataOperators[*int]{
				Default: pointerOf(1),
			},
			want: metadataOperators[*int]{
				Default: pointerOf(1),
			},
		},
		testCaseMetadataOperatorsMerge[int]{
			highOps: metadataOperators[int]{
				Default: 1,
			},
			lowOps: metadataOperators[int]{
				Default: 2,
			},
			wantErr: true,
		},
		testCaseMetadataOperatorsMerge[[]int]{
			highOps: metadataOperators[[]int]{
				Default: nil,
			},
			lowOps: metadataOperators[[]int]{
				Default: nil,
			},
			want: metadataOperators[[]int]{
				Default: nil,
			},
		},
		testCaseMetadataOperatorsMerge[[]int]{
			highOps: metadataOperators[[]int]{
				Default: nil,
			},
			lowOps: metadataOperators[[]int]{
				Default: []int{1},
			},
			want: metadataOperators[[]int]{
				Default: []int{1},
			},
		},
		testCaseMetadataOperatorsMerge[[]int]{
			highOps: metadataOperators[[]int]{
				Default: []int{1},
			},
			lowOps: metadataOperators[[]int]{
				Default: nil,
			},
			want: metadataOperators[[]int]{
				Default: []int{1},
			},
		},
		testCaseMetadataOperatorsMerge[[]int]{
			highOps: metadataOperators[[]int]{
				Default: []int{1},
			},
			lowOps: metadataOperators[[]int]{
				Default: []int{1},
			},
			want: metadataOperators[[]int]{
				Default: []int{1},
			},
		},
		testCaseMetadataOperatorsMerge[[]int]{
			highOps: metadataOperators[[]int]{
				Default: []int{1},
			},
			lowOps: metadataOperators[[]int]{
				Default: []int{2},
			},
			wantErr: true,
		},
		testCaseMetadataOperatorsMerge[int]{
			highOps: metadataOperators[int]{
				OneOf: nil,
			},
			lowOps: metadataOperators[int]{
				OneOf: nil,
			},
			want: metadataOperators[int]{
				OneOf: nil,
			},
		},
		testCaseMetadataOperatorsMerge[int]{
			highOps: metadataOperators[int]{
				OneOf: []int{1},
			},
			lowOps: metadataOperators[int]{
				OneOf: nil,
			},
			want: metadataOperators[int]{
				OneOf: []int{1},
			},
		},
		testCaseMetadataOperatorsMerge[int]{
			highOps: metadataOperators[int]{
				OneOf: nil,
			},
			lowOps: metadataOperators[int]{
				OneOf: []int{1},
			},
			want: metadataOperators[int]{
				OneOf: []int{1},
			},
		},
		testCaseMetadataOperatorsMerge[int]{
			highOps: metadataOperators[int]{
				OneOf: []int{1, 2},
			},
			lowOps: metadataOperators[int]{
				OneOf: []int{2, 3},
			},
			want: metadataOperators[int]{
				OneOf: []int{2},
			},
		},
		testCaseMetadataOperatorsMerge[int]{
			highOps: metadataOperators[int]{
				OneOf: []int{1, 2},
			},
			lowOps: metadataOperators[int]{
				OneOf: []int{3},
			},
			wantErr: true,
		},
		testCaseMetadataOperatorsMerge[[]int]{
			highOps: metadataOperators[[]int]{
				SubsetOf: nil,
			},
			lowOps: metadataOperators[[]int]{
				SubsetOf: nil,
			},
			want: metadataOperators[[]int]{
				SubsetOf: nil,
			},
		},
		testCaseMetadataOperatorsMerge[[]int]{
			highOps: metadataOperators[[]int]{
				SubsetOf: []int{1},
			},
			lowOps: metadataOperators[[]int]{
				SubsetOf: nil,
			},
			want: metadataOperators[[]int]{
				SubsetOf: []int{1},
			},
		},
		testCaseMetadataOperatorsMerge[[]int]{
			highOps: metadataOperators[[]int]{
				SubsetOf: nil,
			},
			lowOps: metadataOperators[[]int]{
				SubsetOf: []int{1},
			},
			want: metadataOperators[[]int]{
				SubsetOf: []int{1},
			},
		},
		testCaseMetadataOperatorsMerge[[]int]{
			highOps: metadataOperators[[]int]{
				SubsetOf: []int{1, 2},
			},
			lowOps: metadataOperators[[]int]{
				SubsetOf: []int{2, 3},
			},
			want: metadataOperators[[]int]{
				SubsetOf: []int{2},
			},
		},
		testCaseMetadataOperatorsMerge[[]int]{
			highOps: metadataOperators[[]int]{
				SubsetOf: []int{1, 2},
			},
			lowOps: metadataOperators[[]int]{
				SubsetOf: []int{3},
			},
			wantErr: true,
		},
		testCaseMetadataOperatorsMerge[[]int]{
			highOps: metadataOperators[[]int]{
				SupersetOf: nil,
			},
			lowOps: metadataOperators[[]int]{
				SupersetOf: nil,
			},
			want: metadataOperators[[]int]{
				SupersetOf: nil,
			},
		},
		testCaseMetadataOperatorsMerge[[]string]{
			highOps: metadataOperators[[]string]{
				SupersetOf: []string{"test1"},
			},
			lowOps: metadataOperators[[]string]{
				SupersetOf: nil,
			},
			want: metadataOperators[[]string]{
				SupersetOf: []string{"test1"},
			},
		},
		testCaseMetadataOperatorsMerge[[]string]{
			highOps: metadataOperators[[]string]{
				SupersetOf: nil,
			},
			lowOps: metadataOperators[[]string]{
				SupersetOf: []string{"test1"},
			},
			want: metadataOperators[[]string]{
				SupersetOf: []string{"test1"},
			},
		},
		testCaseMetadataOperatorsMerge[[]string]{
			highOps: metadataOperators[[]string]{
				SupersetOf: []string{"test1"},
			},
			lowOps: metadataOperators[[]string]{
				SupersetOf: []string{"test2"},
			},
			want: metadataOperators[[]string]{
				SupersetOf: []string{"test1", "test2"},
			},
		},
		testCaseMetadataOperatorsMerge[int]{
			highOps: metadataOperators[int]{
				Essential: false,
			},
			lowOps: metadataOperators[int]{
				Essential: false,
			},
			want: metadataOperators[int]{
				Essential: false,
			},
		},
		testCaseMetadataOperatorsMerge[int]{
			highOps: metadataOperators[int]{
				Essential: false,
			},
			lowOps: metadataOperators[int]{
				Essential: true,
			},
			want: metadataOperators[int]{
				Essential: true,
			},
		},
		testCaseMetadataOperatorsMerge[int]{
			highOps: metadataOperators[int]{
				Essential: true,
			},
			lowOps: metadataOperators[int]{
				Essential: false,
			},
			want: metadataOperators[int]{
				Essential: true,
			},
		},
		testCaseMetadataOperatorsMerge[int]{
			highOps: metadataOperators[int]{
				Essential: true,
			},
			lowOps: metadataOperators[int]{
				Essential: true,
			},
			want: metadataOperators[int]{
				Essential: true,
			},
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), testCase.runTest)
	}
}

type testCaseMetadataOperatorsMerge[T any] struct {
	highOps metadataOperators[T]
	lowOps  metadataOperators[T]
	want    metadataOperators[T]
	wantErr bool
}

func (testCase testCaseMetadataOperatorsMerge[T]) runTest(t *testing.T) {
	// When.
	got, err := testCase.highOps.Merge(testCase.lowOps)

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

func TestMetadataOperators_Apply(t *testing.T) {
	// Given.
	testCases := []testCaseInterface{
		testCaseMetadataOperatorsApply[int]{
			ops: metadataOperators[int]{
				Value: nullable[int]{
					Set: false,
				},
			},
			field: 1,
			want:  1,
		},
		testCaseMetadataOperatorsApply[string]{
			ops: metadataOperators[string]{
				Value: nullable[string]{
					Set: false,
				},
			},
			field: "test",
			want:  "test",
		},
		testCaseMetadataOperatorsApply[int]{
			ops: metadataOperators[int]{
				Value: nullable[int]{
					Set:   true,
					Value: 1,
				},
			},
			field: 2,
			want:  1,
		},
		testCaseMetadataOperatorsApply[string]{
			ops: metadataOperators[string]{
				Value: nullable[string]{
					Set:   true,
					Value: "test",
				},
			},
			field: "random",
			want:  "test",
		},
		testCaseMetadataOperatorsApply[*int]{
			ops: metadataOperators[*int]{
				Value: nullable[*int]{
					Set:   true,
					Value: nil,
				},
			},
			field: pointerOf(1),
			want:  nil,
		},
		testCaseMetadataOperatorsApply[*string]{
			ops: metadataOperators[*string]{
				Value: nullable[*string]{
					Set:   true,
					Value: nil,
				},
			},
			field: pointerOf("test"),
			want:  nil,
		},
		testCaseMetadataOperatorsApply[[]int]{
			ops: metadataOperators[[]int]{
				Value: nullable[[]int]{
					Set: false,
				},
			},
			field: []int{1},
			want:  []int{1},
		},
		testCaseMetadataOperatorsApply[[]string]{
			ops: metadataOperators[[]string]{
				Value: nullable[[]string]{
					Set: false,
				},
			},
			field: []string{"test"},
			want:  []string{"test"},
		},
		testCaseMetadataOperatorsApply[[]int]{
			ops: metadataOperators[[]int]{
				Value: nullable[[]int]{
					Set:   true,
					Value: []int{1},
				},
			},
			field: []int{2},
			want:  []int{1},
		},
		testCaseMetadataOperatorsApply[[]string]{
			ops: metadataOperators[[]string]{
				Value: nullable[[]string]{
					Set:   true,
					Value: []string{"test"},
				},
			},
			field: []string{"random"},
			want:  []string{"test"},
		},
		testCaseMetadataOperatorsApply[[]int]{
			ops: metadataOperators[[]int]{
				Value: nullable[[]int]{
					Set:   true,
					Value: nil,
				},
			},
			field: []int{1},
			want:  nil,
		},
		testCaseMetadataOperatorsApply[[]int]{
			ops: metadataOperators[[]int]{
				Add: nil,
			},
			field: []int{1},
			want:  []int{1},
		},
		testCaseMetadataOperatorsApply[[]int]{
			ops: metadataOperators[[]int]{
				Add: []int{1},
			},
			field: []int{1},
			want:  []int{1},
		},
		testCaseMetadataOperatorsApply[[]int]{
			ops: metadataOperators[[]int]{
				Add: []int{1, 2},
			},
			field: []int{1},
			want:  []int{1, 2},
		},
		testCaseMetadataOperatorsApply[[]int]{
			ops: metadataOperators[[]int]{
				Add: []int{1},
			},
			field: []int{1, 3},
			want:  []int{1, 3},
		},
		testCaseMetadataOperatorsApply[[]string]{
			ops: metadataOperators[[]string]{
				Add: []string{"test"},
			},
			field: []string{"test"},
			want:  []string{"test"},
		},
		testCaseMetadataOperatorsApply[int]{
			ops: metadataOperators[int]{
				Default: 0,
			},
			field: 0,
			want:  0,
		},
		testCaseMetadataOperatorsApply[int]{
			ops: metadataOperators[int]{
				Default: 0,
			},
			field: 1,
			want:  1,
		},
		testCaseMetadataOperatorsApply[string]{
			ops: metadataOperators[string]{
				Default: "",
			},
			field: "test",
			want:  "test",
		},
		testCaseMetadataOperatorsApply[int]{
			ops: metadataOperators[int]{
				Default: 1,
			},
			field: 0,
			want:  1,
		},
		testCaseMetadataOperatorsApply[*int]{
			ops: metadataOperators[*int]{
				Default: pointerOf(1),
			},
			field: pointerOf(1),
			want:  pointerOf(1),
		},
		testCaseMetadataOperatorsApply[[]int]{
			ops: metadataOperators[[]int]{
				Default: nil,
			},
			field: []int{1},
			want:  []int{1},
		},
		testCaseMetadataOperatorsApply[[]int]{
			ops: metadataOperators[[]int]{
				Default: nil,
			},
			field: nil,
			want:  nil,
		},
		testCaseMetadataOperatorsApply[[]string]{
			ops: metadataOperators[[]string]{
				Default: []string{"test1"},
			},
			field: []string{"test"},
			want:  []string{"test"},
		},
		testCaseMetadataOperatorsApply[[]int]{
			ops: metadataOperators[[]int]{
				Default: []int{1},
			},
			field: nil,
			want:  []int{1},
		},
		testCaseMetadataOperatorsApply[[]*int]{
			ops: metadataOperators[[]*int]{
				Default: []*int{pointerOf(1)},
			},
			field: []*int{pointerOf(1)},
			want:  []*int{pointerOf(1)},
		},
		testCaseMetadataOperatorsApply[int]{
			ops: metadataOperators[int]{
				OneOf: nil,
			},
			field: 0,
			want:  0,
		},
		testCaseMetadataOperatorsApply[int]{
			ops: metadataOperators[int]{
				OneOf: nil,
			},
			field: 1,
			want:  1,
		},
		testCaseMetadataOperatorsApply[string]{
			ops: metadataOperators[string]{
				OneOf: nil,
			},
			field: "test",
			want:  "test",
		},
		testCaseMetadataOperatorsApply[int]{
			ops: metadataOperators[int]{
				OneOf: []int{0, 1},
			},
			field: 1,
			want:  1,
		},
		testCaseMetadataOperatorsApply[int]{
			ops: metadataOperators[int]{
				OneOf: []int{0, 1},
			},
			field:   2,
			wantErr: true,
		},
		testCaseMetadataOperatorsApply[[]int]{
			ops: metadataOperators[[]int]{
				SubsetOf: nil,
			},
			field: nil,
			want:  nil,
		},
		testCaseMetadataOperatorsApply[[]int]{
			ops: metadataOperators[[]int]{
				SubsetOf: nil,
			},
			field: []int{1},
			want:  []int{1},
		},
		testCaseMetadataOperatorsApply[[]int]{
			ops: metadataOperators[[]int]{
				SubsetOf: []int{1, 2, 3},
			},
			field: []int{1, 2},
			want:  []int{1, 2},
		},
		testCaseMetadataOperatorsApply[[]int]{
			ops: metadataOperators[[]int]{
				SubsetOf: []int{1, 2},
			},
			field:   []int{3},
			wantErr: true,
		},
		testCaseMetadataOperatorsApply[[]int]{
			ops: metadataOperators[[]int]{
				SupersetOf: nil,
			},
			field: nil,
			want:  nil,
		},
		testCaseMetadataOperatorsApply[[]int]{
			ops: metadataOperators[[]int]{
				SupersetOf: nil,
			},
			field: []int{1},
			want:  []int{1},
		},
		testCaseMetadataOperatorsApply[[]int]{
			ops: metadataOperators[[]int]{
				SupersetOf: []int{1, 2, 3},
			},
			field: []int{1, 2, 3},
			want:  []int{1, 2, 3},
		},
		testCaseMetadataOperatorsApply[[]int]{
			ops: metadataOperators[[]int]{
				SupersetOf: []int{1, 2},
			},
			field:   []int{3},
			wantErr: true,
		},
		testCaseMetadataOperatorsApply[[]int]{
			ops: metadataOperators[[]int]{
				SupersetOf: []int{1},
			},
			field:   nil,
			wantErr: true,
		},
		testCaseMetadataOperatorsApply[int]{
			ops: metadataOperators[int]{
				Essential: false,
			},
			field: 1,
			want:  1,
		},
		testCaseMetadataOperatorsApply[int]{
			ops: metadataOperators[int]{
				Essential: false,
			},
			field: 0,
			want:  0,
		},
		testCaseMetadataOperatorsApply[int]{
			ops: metadataOperators[int]{
				Essential: true,
			},
			field: 1,
			want:  1,
		},
		testCaseMetadataOperatorsApply[*int]{
			ops: metadataOperators[*int]{
				Essential: true,
			},
			field: pointerOf(1),
			want:  pointerOf(1),
		},
		testCaseMetadataOperatorsApply[int]{
			ops: metadataOperators[int]{
				Essential: true,
			},
			field:   0,
			wantErr: true,
		},
		testCaseMetadataOperatorsApply[*int]{
			ops: metadataOperators[*int]{
				Essential: true,
			},
			field:   nil,
			wantErr: true,
		},
		testCaseMetadataOperatorsApply[[]int]{
			ops: metadataOperators[[]int]{
				Essential: false,
			},
			field: []int{1},
			want:  []int{1},
		},
		testCaseMetadataOperatorsApply[[]int]{
			ops: metadataOperators[[]int]{
				Essential: false,
			},
			field: nil,
			want:  nil,
		},
		testCaseMetadataOperatorsApply[[]int]{
			ops: metadataOperators[[]int]{
				Essential: true,
			},
			field: []int{1},
			want:  []int{1},
		},
		testCaseMetadataOperatorsApply[[]int]{
			ops: metadataOperators[[]int]{
				Essential: true,
			},
			field:   nil,
			wantErr: true,
		},
	}

	// When.
	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %d", i), testCase.runTest)
	}
}

type testCaseMetadataOperatorsApply[T any] struct {
	ops     metadataOperators[T]
	field   T
	want    T
	wantErr bool
}

func (testCase testCaseMetadataOperatorsApply[T]) runTest(t *testing.T) {
	// When.
	got, err := testCase.ops.Apply(testCase.field)

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

type testCaseInterface interface {
	runTest(t *testing.T)
}

func pointerOf[T any](t T) *T {
	return &t
}

func TestMetadataOperators_Validate(t *testing.T) {
	testCases := []struct {
		name    string
		ops     metadataOperators[int]
		wantErr bool
	}{
		{
			name:    "empty operators valid",
			ops:     metadataOperators[int]{},
			wantErr: false,
		},
		{
			name: "value set valid",
			ops: metadataOperators[int]{
				Value: nullable[int]{Set: true, Value: 1},
			},
			wantErr: false,
		},
		{
			name: "one_of valid",
			ops: metadataOperators[int]{
				OneOf: []int{1, 2, 3},
			},
			wantErr: false,
		},
		{
			name: "value not in one_of invalid",
			ops: metadataOperators[int]{
				Value: nullable[int]{Set: true, Value: 5},
				OneOf: []int{1, 2, 3},
			},
			wantErr: true,
		},
		{
			name: "value cannot combine with one_of",
			ops: metadataOperators[int]{
				Value: nullable[int]{Set: true, Value: 2},
				OneOf: []int{1, 2, 3},
			},
			wantErr: true, // value cannot be combined with other operators except essential
		},
		{
			name: "default not in one_of invalid",
			ops: metadataOperators[int]{
				Default: 5,
				OneOf:   []int{1, 2, 3},
			},
			wantErr: true,
		},
		{
			name: "default in one_of valid",
			ops: metadataOperators[int]{
				Default: 2,
				OneOf:   []int{1, 2, 3},
			},
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.ops.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestMetadataOperators_ValidateSlice(t *testing.T) {
	testCases := []struct {
		name    string
		ops     metadataOperators[[]int]
		wantErr bool
	}{
		{
			name:    "empty operators valid",
			ops:     metadataOperators[[]int]{},
			wantErr: false,
		},
		{
			name: "subset_of valid",
			ops: metadataOperators[[]int]{
				SubsetOf: []int{1, 2, 3},
			},
			wantErr: false,
		},
		{
			name: "superset_of valid",
			ops: metadataOperators[[]int]{
				SupersetOf: []int{1, 2},
			},
			wantErr: false,
		},
		{
			name: "value not subset_of invalid",
			ops: metadataOperators[[]int]{
				Value:    nullable[[]int]{Set: true, Value: []int{1, 5}},
				SubsetOf: []int{1, 2, 3},
			},
			wantErr: true,
		},
		{
			name: "value cannot combine with subset_of",
			ops: metadataOperators[[]int]{
				Value:    nullable[[]int]{Set: true, Value: []int{1, 2}},
				SubsetOf: []int{1, 2, 3},
			},
			wantErr: true, // value cannot be combined with other operators except essential
		},
		{
			name: "superset_of not subset_of invalid",
			ops: metadataOperators[[]int]{
				SubsetOf:   []int{1, 2},
				SupersetOf: []int{1, 2, 3},
			},
			wantErr: true,
		},
		{
			name: "superset_of is subset_of valid",
			ops: metadataOperators[[]int]{
				SubsetOf:   []int{1, 2, 3, 4},
				SupersetOf: []int{1, 2},
			},
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.ops.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestMetadataOperators_ApplyEssential(t *testing.T) {
	t.Run("essential true with zero value fails", func(t *testing.T) {
		ops := metadataOperators[int]{Essential: true}
		_, err := ops.Apply(0)
		if err == nil {
			t.Error("expected error for essential field with zero value")
		}
	})

	t.Run("essential true with non-zero value passes", func(t *testing.T) {
		ops := metadataOperators[int]{Essential: true}
		result, err := ops.Apply(5)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result != 5 {
			t.Errorf("result = %d, want 5", result)
		}
	})

	t.Run("essential false with zero value passes", func(t *testing.T) {
		ops := metadataOperators[int]{Essential: false}
		result, err := ops.Apply(0)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result != 0 {
			t.Errorf("result = %d, want 0", result)
		}
	})

	t.Run("essential true with nil pointer fails", func(t *testing.T) {
		ops := metadataOperators[*int]{Essential: true}
		_, err := ops.Apply(nil)
		if err == nil {
			t.Error("expected error for essential field with nil pointer")
		}
	})

	t.Run("essential true with non-nil pointer passes", func(t *testing.T) {
		ops := metadataOperators[*int]{Essential: true}
		val := 5
		result, err := ops.Apply(&val)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if *result != 5 {
			t.Errorf("*result = %d, want 5", *result)
		}
	})

	t.Run("essential true with empty string fails", func(t *testing.T) {
		ops := metadataOperators[string]{Essential: true}
		_, err := ops.Apply("")
		if err == nil {
			t.Error("expected error for essential field with empty string")
		}
	})

	t.Run("essential true with non-empty string passes", func(t *testing.T) {
		ops := metadataOperators[string]{Essential: true}
		result, err := ops.Apply("value")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result != "value" {
			t.Errorf("result = %q, want %q", result, "value")
		}
	})

	t.Run("essential true with nil slice fails", func(t *testing.T) {
		ops := metadataOperators[[]int]{Essential: true}
		_, err := ops.Apply(nil)
		if err == nil {
			t.Error("expected error for essential field with nil slice")
		}
	})

	t.Run("essential true with non-empty slice passes", func(t *testing.T) {
		ops := metadataOperators[[]int]{Essential: true}
		result, err := ops.Apply([]int{1, 2})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(result) != 2 {
			t.Errorf("len(result) = %d, want 2", len(result))
		}
	})
}
