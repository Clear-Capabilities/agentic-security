{-# LANGUAGE OverloadedStrings #-}
-- Auth helpers shared by the Scotty fixture. requireUser READS a credential and REJECTS when it is absent.
module Auth (requireUser, requireAdmin, requireCookieUser, isAdmin, User(..)) where

import Web.Scotty
import Network.HTTP.Types (status401, status403)
import qualified Data.Text.Lazy as TL

data User = User { userId :: Int, userRole :: String }

lookupToken :: TL.Text -> Maybe User
lookupToken t = if t == "secret-admin" then Just (User 1 "admin") else if t == "secret-user" then Just (User 2 "user") else Nothing

requireUser :: ActionM User
requireUser = do
  h <- header "Authorization"
  case h >>= lookupToken of
    Nothing -> status status401 >> finish
    Just u  -> pure u

isAdmin :: User -> Bool
isAdmin u = userRole u == "admin"

requireAdmin :: ActionM User
requireAdmin = do
  u <- requireUser
  if isAdmin u then pure u else status status403 >> finish

requireCookieUser :: ActionM User
requireCookieUser = do
  c <- header "Cookie"
  case c >>= lookupToken of
    Nothing -> status status401 >> finish
    Just u  -> pure u
