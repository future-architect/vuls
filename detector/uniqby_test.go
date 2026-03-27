//go:build !scanner

package detector

import (
	"reflect"
	"testing"
)

func TestUniqBy(t *testing.T) {
	t.Parallel()

	t.Run("empty slice returns empty", func(t *testing.T) {
		got := uniqBy([]int{}, func(v int) int { return v })
		if len(got) != 0 {
			t.Errorf("expected empty slice, got %v", got)
		}
	})

	t.Run("no duplicates returns same slice", func(t *testing.T) {
		got := uniqBy([]int{1, 2, 3}, func(v int) int { return v })
		want := []int{1, 2, 3}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("duplicates removed, first occurrence kept", func(t *testing.T) {
		got := uniqBy([]int{1, 2, 3, 2, 1, 4}, func(v int) int { return v })
		want := []int{1, 2, 3, 4}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("works with struct key extraction", func(t *testing.T) {
		type item struct {
			ID   int
			Name string
		}
		input := []item{
			{ID: 1, Name: "first"},
			{ID: 2, Name: "second"},
			{ID: 1, Name: "duplicate"},
			{ID: 3, Name: "third"},
		}
		got := uniqBy(input, func(v item) int { return v.ID })
		want := []item{
			{ID: 1, Name: "first"},
			{ID: 2, Name: "second"},
			{ID: 3, Name: "third"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
}
