// Package ruleexpiry transports private expiry deadlines from NetFlow's
// configuration composer to its kernel without changing effective YAML.
package ruleexpiry

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"
)

const prefix = "# netflow-private-rule-expiries:"
const maxDeadlines = 1000

// Encode always inserts a header, including for an empty list, so a comment
// supplied by a subscription cannot impersonate the private header.
func Encode(config []byte, deadlines []time.Time) ([]byte, error) {
	if len(deadlines) > maxDeadlines {
		return nil, errors.New("too many rule expirations")
	}
	values := make([]int64, len(deadlines))
	for i, deadline := range deadlines {
		values[i] = deadline.UnixNano()
		if values[i] <= 0 {
			return nil, errors.New("invalid rule expiration")
		}
	}
	data, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(prefix)+len(data)+1+len(config))
	out = append(out, prefix...)
	out = append(out, data...)
	out = append(out, '\n')
	out = append(out, config...)
	return out, nil
}

// Decode consumes only the first line. A second matching comment is regular
// untrusted YAML input and is never treated as metadata.
func Decode(data []byte) ([]byte, []time.Time, error) {
	if !bytes.HasPrefix(data, []byte(prefix)) {
		return data, nil, nil
	}
	end := bytes.IndexByte(data, '\n')
	if end < 0 || end > 32<<10 {
		return nil, nil, errors.New("invalid rule expiration header")
	}
	var values []int64
	if err := json.Unmarshal(data[len(prefix):end], &values); err != nil || len(values) > maxDeadlines {
		return nil, nil, errors.New("invalid rule expiration header")
	}
	deadlines := make([]time.Time, len(values))
	for i, value := range values {
		if value <= 0 {
			return nil, nil, errors.New("invalid rule expiration")
		}
		deadlines[i] = time.Unix(0, value)
	}
	return data[end+1:], deadlines, nil
}
