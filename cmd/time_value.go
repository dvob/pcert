package cmd

import "time"

type timeValue struct {
	value *time.Time
}

func newTimeValue(t *time.Time) *timeValue {
	return &timeValue{
		value: t,
	}
}

func (t *timeValue) Type() string {
	return "time"
}

func (t *timeValue) String() string {
	if t.value.IsZero() {
		return ""
	}
	return t.value.Format(time.RFC3339)
}

func (t *timeValue) Set(timeStr string) error {
	parsedTime, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return err
	}
	*t.value = parsedTime
	return nil
}
