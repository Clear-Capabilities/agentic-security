package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func remove(w http.ResponseWriter, r *http.Request) {
	os.Remove(filepath.Join("/srv/uploads", filepath.Base(r.PathValue("name"))))
}