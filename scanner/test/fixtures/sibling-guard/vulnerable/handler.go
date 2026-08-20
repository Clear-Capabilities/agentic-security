package handles

import (
	"fmt"
)

// Faithful reduction of GHSA-95cv-r8x4-vh75 (alist, CWE-22). Two sibling
// fields of the same request struct reach a filesystem rename; the project's
// own checkRelativePath guard is applied to NewName and not to SrcName, so
// SrcName can traverse out of reqPath.
func FsBatchRename(c *Context, req *RenameReq, reqPath string) {
	for _, renameObject := range req.RenameObjects {
		if renameObject.SrcName == "" || renameObject.NewName == "" {
			continue
		}
		err := checkRelativePath(renameObject.NewName)
		if err != nil {
			ErrorResp(c, err, 403)
			return
		}
		filePath := fmt.Sprintf("%s/%s", reqPath, renameObject.SrcName)
		if err := fsRename(c, filePath, renameObject.NewName); err != nil {
			ErrorResp(c, err, 500)
			return
		}
	}
}
