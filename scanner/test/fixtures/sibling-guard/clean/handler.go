package handles

import (
	"fmt"
)

// The upstream fix: the same guard is applied to BOTH sibling fields.
func FsBatchRename(c *Context, req *RenameReq, reqPath string) {
	for _, renameObject := range req.RenameObjects {
		if renameObject.SrcName == "" || renameObject.NewName == "" {
			continue
		}
		err := checkRelativePath(renameObject.SrcName)
		if err != nil {
			ErrorResp(c, err, 403)
			return
		}
		err = checkRelativePath(renameObject.NewName)
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
