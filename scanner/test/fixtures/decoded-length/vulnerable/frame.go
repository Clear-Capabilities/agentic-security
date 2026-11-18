package frame

import "encoding/binary"

type Reader interface {
	Uint32() (uint32, error)
}

func ReadBody(r Reader) ([]byte, error) {
	size, err := r.Uint32()
	if err != nil {
		return nil, err
	}
	return make([]byte, size), nil
}

func Command(p []byte) string {
	if len(p) <= 4 {
		return ""
	}
	stop := 4 + binary.BigEndian.Uint32(p[:4])
	if len(p) < int(stop) {
		return ""
	}
	return string(p[4:stop])
}
