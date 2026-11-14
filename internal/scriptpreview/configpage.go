package scriptpreview

import (
	"errors"
	"unicode/utf8"
)

// ConfigPage contains private configuration data and must only be returned
// in response to an explicit request to inspect the full configuration.
type ConfigPage struct {
	Offset     int    `json:"offset"`
	NextOffset int    `json:"next_offset"`
	Total      int    `json:"total"`
	Text       string `json:"text"`
}

// PaginateConfig returns UTF-8-aligned chunks and bounds JSON response size.
func PaginateConfig(body []byte, offset, limit int) (ConfigPage, error) {
	if offset < 0 || offset > len(body) || (offset < len(body) && !utf8.RuneStart(body[offset])) || limit < 0 || limit > 64<<10 {
		return ConfigPage{}, errors.New("invalid configuration page")
	}
	if limit == 0 {
		limit = 64 << 10
	}
	end := offset + limit
	if end > len(body) {
		end = len(body)
	}
	for end < len(body) && end > offset && !utf8.RuneStart(body[end]) {
		end--
	}
	if end == offset && end < len(body) {
		return ConfigPage{}, errors.New("configuration page limit is too small")
	}
	if !utf8.Valid(body[offset:end]) {
		return ConfigPage{}, errors.New("invalid configuration page")
	}
	return ConfigPage{Offset: offset, NextOffset: end, Total: len(body), Text: string(body[offset:end])}, nil
}
