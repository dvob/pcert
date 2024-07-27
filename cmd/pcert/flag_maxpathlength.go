package main

import (
	"strconv"
)

type maxPathLengthValue struct {
	maxPathLen *int
}

func newMaxPathLengthValue(maxPathLen *int) *maxPathLengthValue {
	return &maxPathLengthValue{
		maxPathLen: maxPathLen,
	}
}

func (m *maxPathLengthValue) Type() string {
	return "int|-"
}

func (m *maxPathLengthValue) String() string {
	if m.maxPathLen == nil {
		return "-"
	}
	return strconv.Itoa(*m.maxPathLen)
}

func (m *maxPathLengthValue) Set(length string) error {
	var err error
	if length == "-" {
		m.maxPathLen = nil
	}

	value, err := strconv.Atoi(length)
	if err != nil {
		return err
	}
	m.maxPathLen = &value
	return nil
}
