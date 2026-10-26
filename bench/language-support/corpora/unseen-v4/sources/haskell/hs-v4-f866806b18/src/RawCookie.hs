{-# LANGUAGE OverloadedStrings #-}
module RawCookie (loginApp) where

import Network.Wai
import Network.HTTP.Types
import qualified Data.ByteString.Char8 as B

loginApp :: B.ByteString -> Application
loginApp token _req respond =
  respond (responseLBS status200 [("Set-Cookie", "session=" <> token <> "; Path=/")] "logged in")
