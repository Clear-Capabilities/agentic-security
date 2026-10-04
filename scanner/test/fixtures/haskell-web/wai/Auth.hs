{-# LANGUAGE OverloadedStrings #-}
-- WAI middleware that READS the Authorization header and REJECTS with 401. Imported by Main (cross-file).
module Auth (authMiddleware, passthroughMiddleware) where

import Network.Wai
import Network.HTTP.Types (status401, hAuthorization)

authMiddleware :: Middleware
authMiddleware app req respond =
  case lookup hAuthorization (requestHeaders req) of
    Nothing -> respond (responseLBS status401 [] "unauthorized")
    Just _  -> app req respond

-- Defined but it checks nothing: not an auth guard.
passthroughMiddleware :: Middleware
passthroughMiddleware app req respond = app req respond
