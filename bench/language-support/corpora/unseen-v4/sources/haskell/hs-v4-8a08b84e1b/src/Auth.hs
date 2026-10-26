{-# LANGUAGE OverloadedStrings #-}
module Auth (loginResponse) where

import Network.Wai
import Network.HTTP.Types
import Web.Cookie
import Data.ByteString.Builder (toByteString')
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy as BL

loginResponse :: B.ByteString -> Response
loginResponse token = responseLBS status200 [(hSetCookie, rendered)] "ok"
  where
    cookie = defaultSetCookie
      { setCookieName = "session"
      , setCookieValue = token
      , setCookieHttpOnly = False
      , setCookieSecure = False
      }
    rendered = toByteString' (renderSetCookie cookie)
