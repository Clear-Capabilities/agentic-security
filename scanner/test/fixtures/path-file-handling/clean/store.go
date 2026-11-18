package store

import (
	"errors"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Store struct {
	root string
}

var errEscapes = errors.New("name escapes the store root")

// nativePath maps an escaped object name to a file under the store root.
func (s *Store) nativePath(name string) (string, error) {
	decoded, err := url.PathUnescape(name)
	if err != nil {
		return "", err
	}
	full := filepath.Join(s.root, decoded)
	rel, err := filepath.Rel(s.root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errEscapes
	}
	return full, nil
}

func Handler(w http.ResponseWriter, r *http.Request) {
	p := strings.Trim(r.URL.Path, "/")
	if p != "" && !fs.ValidPath(p) {
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
	fileMode := os.FileMode(mode).Perm()
	return os.Chmod(target, fileMode)
}

func Within(root, p string) bool {
	absRoot, _ := filepath.Abs(root)
	absPath, _ := filepath.Abs(p)
	prefix := absRoot + string(filepath.Separator)
	return absPath == absRoot || strings.HasPrefix(absPath, prefix)
}
