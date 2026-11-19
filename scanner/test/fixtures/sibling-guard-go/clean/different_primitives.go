// Synthetic fixture: the guarded functions and the unguarded one reach
// DIFFERENT primitives (Update vs a read-only Count), so they are never
// compared.
package docs

import "context"

func (s *Server) RetitleDoc(ctx context.Context, user *User, docID string, title string) error {
	if err := s.authz.RequireDocAccess(user, docID); err != nil {
		return err
	}
	return s.store.Update(ctx, docID, Patch{Title: title})
}

func (s *Server) PinDoc(ctx context.Context, user *User, docID string) error {
	if err := s.authz.RequireDocAccess(user, docID); err != nil {
		return err
	}
	return s.store.Update(ctx, docID, Patch{Pinned: true})
}

func (s *Server) ViewCount(ctx context.Context, docID string) (int, error) {
	return s.metrics.Count(ctx, docID)
}
