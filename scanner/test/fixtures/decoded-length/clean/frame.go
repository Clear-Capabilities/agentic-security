package frame

import (
	"encoding/binary"
	"errors"
)

type Reader interface {
	Uint32() (uint32, error)
	Remaining() int
}

func ReadBody(r Reader) ([]byte, error) {
	size, err := r.Uint32()
	if err != nil {
		return nil, err
	}
	if int(size) > r.Remaining() {
		return nil, errors.New("short frame")
	}
	return make([]byte, size), nil
}

func Command(p []byte) string {
	if len(p) <= 4 {
		return ""
	}
	n := int(binary.BigEndian.Uint32(p[:4]))
	if n > len(p)-4 {
		return ""
	}
	return string(p[4 : 4+n])
}
