package thumbs

import (
	"bytes"
	"errors"
	"image"
	"image/png"
	"io"
)

const maxPixels = 40 * 1000 * 1000

func Load(r io.Reader, kind string) (image.Image, error) {
	var head bytes.Buffer
	cfg, _, err := image.DecodeConfig(io.TeeReader(r, &head))
	if err != nil {
		return nil, err
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || int64(cfg.Width)*int64(cfg.Height) > maxPixels {
		return nil, errors.New("image too large")
	}
	r = io.MultiReader(&head, r)
	switch kind {
	case "png":
		return png.Decode(r)
	default:
		img, _, err := image.Decode(r)
		return img, err
	}
}
