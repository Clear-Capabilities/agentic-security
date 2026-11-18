package notes

import (
	"net/http"
	"os"
	"path/filepath"
)

const notesRoot = "/var/lib/notes"

func noteHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	if name == "" || !filepath.IsLocal(name) {
		http.Error(w, "bad file", http.StatusBadRequest)
		return
	}
	data, err := os.ReadFile(filepath.Join(notesRoot, name))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Write(data)
}
