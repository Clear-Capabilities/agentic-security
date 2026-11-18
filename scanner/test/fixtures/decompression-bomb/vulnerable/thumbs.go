package thumbs

import (
	"image"
	"image/png"
	"io"
)

func Load(r io.Reader, kind string) (image.Image, error) {
	switch kind {
	case "png":
		return png.Decode(r)
	default:
		img, _, err := image.Decode(r)
		return img, err
	}
}
