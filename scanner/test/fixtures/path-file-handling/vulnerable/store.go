package store

import (
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

type Store struct {
	root string
}

// objectPath maps an escaped object name to a file under the store root.
func (s *Store) objectPath(escaped string) string {
	return filepath.Join(s.root, mustUnescape(url.PathUnescape(escaped)))
}

func mustUnescape(v string, _ error) string { return v }

func Handler(w http.ResponseWriter, r *http.Request) {
	p := strings.Trim(r.URL.Path, "/")
	if p != "" && path.Clean(p) != p {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	w.Write([]byte(p))
}

func ApplyMode(target string, attrs map[string]string) error {
	mode, err := strconv.ParseUint(attrs["mode"], 8, 32)
	if err != nil {
		return err
	}
	fileMode := os.FileMode(mode)
	return os.Chmod(target, fileMode)
}

func Within(root, p string) bool {
	absRoot, _ := filepath.Abs(root)
	absPath, _ := filepath.Abs(p)
	return strings.HasPrefix(absPath, absRoot)
}
