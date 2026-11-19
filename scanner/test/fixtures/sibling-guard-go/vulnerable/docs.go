// Synthetic fixture: RenameDoc and ShareDoc check the caller's access to the
// document before updating it, ArchiveDoc updates it with no check.
package docs

import "context"

type Server struct {
	authz Authorizer
	store Store
}

func (s *Server) RenameDoc(ctx context.Context, user *User, docID string, title string) error {
	if err := s.authz.RequireDocAccess(user, docID); err != nil {
		return err
	}
	return s.store.Update(ctx, docID, Patch{Title: title})
}

func (s *Server) ShareDoc(ctx context.Context, user *User, docID string, with string) error {
	if err := s.authz.RequireDocAccess(user, docID); err != nil {
		return err
	}
	return s.store.Update(ctx, docID, Patch{SharedWith: with})
}

func (s *Server) ArchiveDoc(ctx context.Context, user *User, docID string) error {
	return s.store.Update(ctx, docID, Patch{Archived: true})
}
