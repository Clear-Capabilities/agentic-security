package api

import (
	"archive/zip"
	"io"
	"net/http"
	"os"
)

const maxBody = 1 << 20
const maxEntry = 10 << 20

func Echo(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}
	w.Write(body)
}

func Import(w http.ResponseWriter, r *http.Request) {
	f, hdr, err := r.FormFile("archive")
	if err != nil {
		return
	}
	zr, err := zip.NewReader(f, hdr.Size)
	if err != nil {
		return
	}
	for _, e := range zr.File {
		rc, _ := e.Open()
		out, _ := os.Create("/srv/imports/" + e.Name)
		io.Copy(out, io.LimitReader(rc, maxEntry))
	}
}
