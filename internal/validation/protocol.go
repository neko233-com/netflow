package validation

import (
	"encoding/json"
	"errors"
	"io"
)

const MaxRequest = 128 << 20

// Serve handles a single request from the desktop and exits without starting a kernel.
func Serve(input io.Reader, output io.Writer) error {
	data, err := io.ReadAll(io.LimitReader(input, MaxRequest+1))
	if err != nil {
		return err
	}
	if len(data) > MaxRequest {
		return errors.New("validation request exceeds size limit")
	}
	var request Request
	if err := json.Unmarshal(data, &request); err != nil {
		return err
	}
	result, err := Check(request)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(result)
}
