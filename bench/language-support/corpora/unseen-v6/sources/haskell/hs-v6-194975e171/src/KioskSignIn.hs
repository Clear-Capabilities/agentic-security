{-# LANGUAGE OverloadedStrings #-}
module KioskSignIn (main) where

import Control.Monad.IO.Class (liftIO)
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as B
import Database.SQLite.Simple
import Snap.Core
import Snap.Http.Server (quickHttpServe)

data Credentials = Credentials { loginName :: B.ByteString, loginPassword :: B.ByteString }

main :: IO ()
main = do
  conn <- open "kiosk.db"
  quickHttpServe $ route [("signin", method POST (signInHandler conn))]

signInHandler :: Connection -> Snap ()
signInHandler conn = do
  name <- getPostParam "name"
  pw <- getPostParam "password"
  case Credentials <$> name <*> pw of
    Nothing -> rejected
    Just creds -> do
      accepted <- liftIO (checkCredentials conn creds)
      if accepted then writeBS "welcome" else rejected

checkCredentials :: Connection -> Credentials -> IO Bool
checkCredentials conn creds = do
  rows <- query conn "SELECT password_hash FROM operators WHERE name = ?" (Only (loginName creds))
  pure (any (\(Only stored) -> stored == B16.encode (SHA1.hash (loginPassword creds))) rows)

rejected :: Snap ()
rejected = modifyResponse (setResponseStatus 401 "Unauthorized") >> writeBS "sign in failed"
