package main

import (
	"io"
	"os"
)

func isFile(name string) bool {
	return name != "" && name != "-"
}

// stdin reader abstration for the case when multiple things (certificate, key,
// etc.) are read from stdin.
type stdinKeeper struct {
	data  []byte
	stdin io.Reader
}

func (s *stdinKeeper) read() ([]byte, error) {
	if s.data != nil {
		return s.data, nil
	}

	var err error
	s.data, err = io.ReadAll(s.stdin)
	if err != nil {
		return nil, err
	}
	return s.data, nil
}

func readStdinOrFile(name string, stdin *stdinKeeper) ([]byte, error) {
	if isFile(name) {
		return os.ReadFile(name)
	}

	return stdin.read()
}

func writeStdoutOrFile(name string, data []byte, mode os.FileMode, stdout io.Writer) error {
	if isFile(name) {
		return os.WriteFile(name, data, mode)
	}

	_, err := stdout.Write(data)
	return err
}
