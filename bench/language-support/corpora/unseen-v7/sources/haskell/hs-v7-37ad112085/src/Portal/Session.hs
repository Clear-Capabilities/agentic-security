{-# LANGUAGE OverloadedStrings #-}
module Portal.Session (loginHandler) where

import Control.Monad (replicateM)
import Control.Monad.IO.Class (liftIO)
import Crypto.BCrypt (validatePassword)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as BC
import Snap.Core
import System.Random.MWC (createSystemRandom, uniformR)

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
  gen <- createSystemRandom
  bytes <- replicateM 32 (uniformR (0, 255 :: Int) gen)
  pure (B16.encode (BS.pack (map fromIntegral bytes)))
