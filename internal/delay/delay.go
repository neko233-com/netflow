// Package delay classifies and orders latency samples.
// The rules match Clash Verge Rev's delay.ts (DLY-04, DLY-05).
// Negative sentinels are not measurements: -2 is an in-flight test and
// any other negative value has not been tested.
package delay

// DefaultTimeout is the latency budget in milliseconds when the caller
// does not pass one (DEFAULT_DELAY_TIMEOUT).
const DefaultTimeout = 10000

// Testing is the in-flight sentinel.
const TestingSample = -2

// implausible is the delay, in milliseconds, above which a sample is an
// error rather than a measurement. Verge uses 1e5.
const implausible = 100000

// State is the class of one latency sample.
type State string

const (
	Testing  State = "testing"
	Untested State = "untested"
	Error    State = "error"
	Timeout  State = "timeout"
	Measured State = "measured"
)

// Classify maps a delay in milliseconds to a state.
// timeout is the budget. A non-positive timeout uses DefaultTimeout.
// -2 is testing. Any other negative sample is untested. A sample above
// 100000 is an error. 0, or a sample at or above the budget, is a timeout.
// Every remaining sample is measured.
func Classify(sample, timeout int) State {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	switch {
	case sample == TestingSample:
		return Testing
	case sample < 0:
		return Untested
	case sample > implausible:
		return Error
	case sample == 0 || sample >= timeout:
		return Timeout
	default:
		return Measured
	}
}

// Compare orders two samples for a proxy list. Lower is earlier.
// measured < timeout < error < testing < untested.
// Two measured samples compare by their value, ascending.
// Two samples in any other shared state compare equal.
func Compare(a, b, timeout int) int {
	ra := rank(Classify(a, timeout))
	rb := rank(Classify(b, timeout))
	if ra != rb {
		return ra - rb
	}
	if Classify(a, timeout) != Measured {
		return 0
	}
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func rank(s State) int {
	switch s {
	case Measured:
		return 0
	case Timeout:
		return 1
	case Error:
		return 2
	case Testing:
		return 3
	case Untested:
		return 4
	default:
		return 4
	}
}
