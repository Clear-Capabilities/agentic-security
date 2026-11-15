{-# LANGUAGE OverloadedStrings #-}
module Portal.SessionStart (loginHandler) where

import Control.Monad.IO.Class (liftIO)
import Crypto.BCrypt (validatePassword)
import Crypto.Random (getRandomBytes)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as B64
import qualified Data.ByteString.Char8 as BC
import Snap.Core

import Portal.Accounts (Account(..), lookupAccount, storeSession)

loginHandler :: Snap ()
loginHandler = do
  login <- getPostParam "login"
  pw <- getPostParam "password"
  found <- maybe (pure Nothing) (liftIO . lookupAccount) login
  case (found, pw) of
    (Just acct, Just p) | validatePassword (accountHash acct) p -> do
      token <- liftIO newSessionToken
      liftIO (storeSession (accountId acct) token)
      modifyResponse (setContentType "application/json")
      writeBS (BC.concat ["{\"token\":\"", token, "\"}"])
    _ -> do
      modifyResponse (setResponseStatus 401 "Unauthorized")
      writeBS "login failed"

newSessionToken :: IO BS.ByteString
newSessionToken = do
  bytes <- getRandomBytes 32 :: IO BS.ByteString
  pure (B64.encodeUnpadded bytes)
