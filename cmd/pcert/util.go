package main

import (
	"fmt"
	"strconv"
	"time"
)

func parseDuration(str string) (time.Duration, error) {
	if str == "" {
		return 0, fmt.Errorf("failed to parse duration: empty string")
	}

	multiplier := time.Hour * 24
	suffix := str[len(str)-1]
	if suffix == 'd' {
		str = str[:len(str)-1]
	} else if suffix == 'y' {
		multiplier = time.Hour * 24 * 365
		str = str[:len(str)-1]
	}
	value, err := strconv.Atoi(str)
	if err != nil {
		return 0, err
	}

	return multiplier * time.Duration(value), nil
}

func formatDuration(d time.Duration) string {
	rest := d % (time.Hour * 24)
	days := int((d - rest).Hours()) / 24
	if rest == time.Duration(0) {
		return fmt.Sprintf("%dd", days)
	} else {
		return fmt.Sprintf("%dd%s", days, rest)
	}
}

type durationValue struct {
	value *time.Duration
}

func newDurationValue(d *time.Duration) *durationValue {
	return &durationValue{
		value: d,
	}
}

func (d *durationValue) Type() string {
	return "duration"
}

func (d *durationValue) String() string {
	return formatDuration(*d.value)
}

func (d *durationValue) Set(str string) (err error) {
	*d.value, err = parseDuration(str)
	return
}
