package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// DecodeJSON decodes exactly one UTF-8 JSON value into destination. The complete
// input, including surrounding whitespace, must fit within maxBytes. The
// function reads at most maxBytes+1 bytes.
func DecodeJSON(reader io.Reader, maxBytes int64, destination any) error {
	if maxBytes <= 0 {
		return errors.New("maximum JSON size must be positive")
	}

	data, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return fmt.Errorf("read JSON: %w", err)
	}

	if int64(len(data)) > maxBytes {
		return fmt.Errorf("JSON exceeds the %d-byte limit", maxBytes)
	}

	if !utf8.Valid(data) {
		return errors.New("JSON is not valid UTF-8")
	}

	return json.Unmarshal(data, destination)
}
