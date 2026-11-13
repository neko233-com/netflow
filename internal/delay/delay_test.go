package delay

import (
	"sort"
	"testing"
)

func TestClassify(t *testing.T) {
	t.Parallel()
	cases := []struct {
		sample  int
		timeout int
		want    State
	}{
		{sample: TestingSample, timeout: DefaultTimeout, want: Testing},
		{sample: -1, timeout: DefaultTimeout, want: Untested},
		{sample: -3, timeout: DefaultTimeout, want: Untested},
		{sample: 0, timeout: DefaultTimeout, want: Timeout},
		{sample: DefaultTimeout, timeout: DefaultTimeout, want: Timeout},
		{sample: DefaultTimeout - 1, timeout: DefaultTimeout, want: Measured},
		{sample: implausible, timeout: DefaultTimeout, want: Timeout},
		{sample: implausible + 1, timeout: DefaultTimeout, want: Error},
		{sample: implausible + 1, timeout: 1_000_000, want: Error},
		{sample: implausible, timeout: 1_000_000, want: Measured},
		{sample: 5000, timeout: 0, want: Measured},
		{sample: DefaultTimeout, timeout: 0, want: Timeout},
	}
	for _, tc := range cases {
		if got := Classify(tc.sample, tc.timeout); got != tc.want {
			t.Errorf("Classify(%d, %d) = %s, want %s", tc.sample, tc.timeout, got, tc.want)
		}
	}
}

func TestCompare(t *testing.T) {
	t.Parallel()
	const timeout = DefaultTimeout
	if Compare(5, 20, timeout) >= 0 || Compare(20, 5, timeout) <= 0 || Compare(5, 5, timeout) != 0 {
		t.Fatal("measured samples should sort by value")
	}
	if Compare(5, 0, timeout) >= 0 {
		t.Fatal("measured should precede timeout")
	}
	if Compare(0, 1_000_000, timeout) >= 0 {
		t.Fatal("timeout should precede error")
	}
	if Compare(1_000_000, TestingSample, timeout) >= 0 {
		t.Fatal("error should precede testing")
	}
	if Compare(TestingSample, -1, timeout) >= 0 {
		t.Fatal("testing should precede untested")
	}
	if Compare(0, timeout, timeout) != 0 || Compare(1_000_000, 1_000_001, timeout) != 0 {
		t.Fatal("shared non-measured states should compare equal")
	}

	samples := []int{-1, TestingSample, 1_000_000, 0, 20, 5}
	sort.SliceStable(samples, func(i, j int) bool {
		return Compare(samples[i], samples[j], timeout) < 0
	})
	want := []int{5, 20, 0, 1_000_000, TestingSample, -1}
	for i := range want {
		if samples[i] != want[i] {
			t.Fatalf("order %v, want %v", samples, want)
		}
	}
}
