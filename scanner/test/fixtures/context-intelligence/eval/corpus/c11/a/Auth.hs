module Auth (requireUser, User(..)) where

import Web.Scotty
import Network.HTTP.Types.Status (status401)

data User = User { userId :: Int, userName :: String }

lookupToken :: String -> Maybe User
lookupToken t = if t == "secret-user" then Just (User 2 "user") else Nothing

requireUser :: ActionM User
requireUser = do
  h <- header "Authorization"
  case fmap show h >>= lookupToken of
    Nothing -> status status401 >> finish
    Just u  -> pure u
