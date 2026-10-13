// Package strictjson rejects ambiguous JSON at policy trust boundaries.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"
)

const maximumDepth = 32

// Decode accepts one bounded JSON value, without duplicate keys, invalid UTF-8,
// unknown struct fields, excessive nesting, or trailing input.
func Decode(data []byte, target any, limit int) error {
	if len(data) == 0 || len(data) > limit || limit <= 0 {
		return errors.New("strictjson: invalid input size")
	}
	if !utf8.Valid(data) {
		return errors.New("strictjson: invalid utf-8")
	}
	if !json.Valid(data) {
		return errors.New("strictjson: invalid structure")
	}
	// Let encoding/json validate the grammar once. A structural walk then
	// checks the additional trust-boundary constraints without allocating a
	// Decoder.Token value for every string, number and delimiter.
	scanner := structureScanner{data: data}
	if err := scanner.value(0); err != nil {
		return fmt.Errorf("strictjson: invalid structure: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		// Do not reproduce attacker-controlled keys or values in diagnostics.
		return errors.New("strictjson: value does not match schema")
	}
	return nil
}

// Object checks exact, case-sensitive keys and non-null required fields.
// encoding/json otherwise matches struct field names case-insensitively.
func Object(data []byte, required, optional []string, limit int) error {
	object := map[string]json.RawMessage{}
	if err := Decode(data, &object, limit); err != nil {
		return err
	}
	if object == nil {
		return errors.New("strictjson: object required")
	}
	allowed := make(map[string]bool, len(required)+len(optional))
	for _, key := range required {
		allowed[key] = true
		value, exists := object[key]
		if !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("strictjson: required field missing or null")
		}
	}
	for _, key := range optional {
		allowed[key] = true
	}
	for key, value := range object {
		if !allowed[key] || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("strictjson: unknown or null field")
		}
	}
	return nil
}

// structureScanner only visits input already accepted by json.Valid. It does
// not implement JSON grammar or decode values; the standard decoder retains
// responsibility for both syntax and mapping into the caller's schema.
type structureScanner struct {
	data   []byte
	offset int
}

func (s *structureScanner) value(depth int) error {
	if depth > maximumDepth {
		return errors.New("nesting limit exceeded")
	}
	s.whitespace()
	switch s.data[s.offset] {
	case '{':
		s.offset++
		s.whitespace()
		seen := map[string]bool{}
		for s.data[s.offset] != '}' {
			start := s.offset
			escaped := s.string()
			key := string(s.data[start+1 : s.offset-1])
			if escaped {
				// Use the standard decoder to canonicalize JSON escapes,
				// including surrogate pairs and unpaired-surrogate replacement.
				if err := json.Unmarshal(s.data[start:s.offset], &key); err != nil {
					return errors.New("invalid object key")
				}
			}
			if seen[key] {
				return errors.New("duplicate or invalid object key")
			}
			seen[key] = true
			s.whitespace()
			s.offset++ // Colon; grammar was checked by json.Valid.
			if err := s.value(depth + 1); err != nil {
				return err
			}
			s.whitespace()
			if s.data[s.offset] == ',' {
				s.offset++
				s.whitespace()
			}
		}
		s.offset++
	case '[':
		s.offset++
		s.whitespace()
		for s.data[s.offset] != ']' {
			if err := s.value(depth + 1); err != nil {
				return err
			}
			s.whitespace()
			if s.data[s.offset] == ',' {
				s.offset++
				s.whitespace()
			}
		}
		s.offset++
	case '"':
		s.string()
	default:
		// Numbers and literals cannot contain delimiters or whitespace.
		for s.offset < len(s.data) {
			switch s.data[s.offset] {
			case ',', '}', ']', ' ', '\t', '\r', '\n':
				return nil
			}
			s.offset++
		}
	}
	return nil
}

func (s *structureScanner) whitespace() {
	for s.offset < len(s.data) {
		switch s.data[s.offset] {
		case ' ', '\t', '\r', '\n':
			s.offset++
		default:
			return
		}
	}
}

func (s *structureScanner) string() bool {
	escaped := false
	s.offset++ // Opening quote.
	for {
		switch s.data[s.offset] {
		case '\\':
			escaped = true
			s.offset += 2
		case '"':
			s.offset++
			return escaped
		default:
			s.offset++
		}
	}
}
