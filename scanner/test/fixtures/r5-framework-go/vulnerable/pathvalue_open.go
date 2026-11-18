package main

import (
	"net/http"
	"os"
)

func remove(w http.ResponseWriter, r *http.Request) {
	os.Remove("/srv/uploads/" + r.PathValue("name"))
}