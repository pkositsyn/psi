package io

import (
	"io"
)

type ReadResetter interface {
	Read() ([]string, error)
	Reset()
}

func LineCount(r ReadResetter) int {
	var count int

	defer r.Reset()

	for {
		_, err := r.Read()
		if err == io.EOF {
			return count
		}
		if err != nil {
			return 0
		}
		count++
	}
}
