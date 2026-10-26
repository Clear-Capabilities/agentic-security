{-# LANGUAGE OverloadedStrings #-}
module SetSession (startSession) where

import Web.Scotty
import Web.Cookie
import Data.ByteString.Builder (toLazyByteString)
import qualified Data.ByteString.Char8 as B
import qualified Data.Text.Lazy.Encoding as TLE

startSession :: B.ByteString -> ActionM ()
startSession sid = do
  let cookie = defaultSetCookie
        { setCookieName = "sid", setCookieValue = sid, setCookiePath = Just "/"
        , setCookieHttpOnly = True, setCookieSecure = True, setCookieSameSite = Just sameSiteStrict }
  setHeader "Set-Cookie" (TLE.decodeUtf8 (toLazyByteString (renderSetCookie cookie)))
  text "welcome"
