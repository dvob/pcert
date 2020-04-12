package main

import (
	"testing"
	"time"
)

func Test_parsDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		err      bool
	}{
		{"1d", time.Hour * 24, false},
		{"3d", time.Hour * 24 * 3, false},
		{"1y", time.Hour * 24 * 365, false},
		{"4y", time.Hour * 24 * 365 * 4, false},
		{"w", 0, true},
		{"", 0, true},
		{"0.5d", 0, true},
	}

	for _, test := range tests {
		result, err := parseDuration(test.input)
		// does no return expected error
		if test.err && err == nil {
			t.Errorf("'%s' has to return error", test.input)
			continue
		}
		// returns error if we don't expect an error
		if err != nil && !test.err {
			t.Errorf("'%s' returned error: %s", test.input, err)
			continue
		}
		if result != test.expected {
			t.Errorf("expected: %s, got: %s", test.expected, result)
		}
	}
}

func Test_formatDuration(t *testing.T) {
	tests := []struct {
		input    time.Duration
		expected string
	}{
		{time.Hour * 24 * 5, "5d"},
		{time.Hour*24*3 + time.Hour*4 + time.Minute*2, "3d4h2m0s"},
	}

	for _, test := range tests {
		result := formatDuration(test.input)
		if result != test.expected {
			t.Errorf("exptected: %s, got: %s", test.expected, result)
		}
	}
}
