{-# LANGUAGE OverloadedStrings #-}
module Badges.Session (badgeLoginHandler) where

import Control.Monad.IO.Class (liftIO)
import Crypto.BCrypt (validatePassword)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Snap.Core
import System.Entropy (getEntropy)

import Badges.Holders (Holder(..), lookupHolder, storeSession)

badgeLoginHandler :: Snap ()
badgeLoginHandler = do
  serial <- getPostParam "serial"
  pin <- getPostParam "pin"
  found <- maybe (pure Nothing) (liftIO . lookupHolder) serial
  case (found, pin) of
    (Just holder, Just p) | validatePassword (holderPinHash holder) p -> do
      token <- liftIO (B16.encode <$> getEntropy 32)
      liftIO (storeSession (holderId holder) token)
      modifyResponse (addResponseCookie (sessionCookie token))
      writeBS "badge session opened"
    _ -> do
      modifyResponse (setResponseStatus 401 "Unauthorized")
      writeBS "pin not accepted"

sessionCookie :: BS.ByteString -> Cookie
sessionCookie token = Cookie
  { cookieName = "badge_session"
  , cookieValue = token
  , cookieExpires = Nothing
  , cookieDomain = Nothing
  , cookiePath = Just "/"
  , cookieSecure = False
  , cookieHttpOnly = False
  }
