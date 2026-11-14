package scriptpreview

import (
	"strings"
	"testing"
)

func TestPaginateConfigPreservesUTF8AndBounds(t *testing.T) {
	input := []byte("a例子z")
	var joined strings.Builder
	for offset := 0; offset < len(input); {
		page, err := PaginateConfig(input, offset, 4)
		if err != nil {
			t.Fatal(err)
		}
		joined.WriteString(page.Text)
		if page.NextOffset <= offset {
			t.Fatal("page made no progress")
		}
		offset = page.NextOffset
	}
	if joined.String() != string(input) {
		t.Fatal("pagination changed configuration")
	}
	if _, err := PaginateConfig(input, 2, 4); err == nil {
		t.Fatal("offset inside rune accepted")
	}
	if _, err := PaginateConfig(input, 0, 1<<17); err == nil {
		t.Fatal("oversize page accepted")
	}
	if _, err := PaginateConfig([]byte{0xff}, 0, 1); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}
