{-# LANGUAGE OverloadedStrings #-}
module Signup (main) where

import Control.Monad.IO.Class (liftIO)
import qualified Crypto.Hash.MD5 as MD5
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text.Lazy as TL
import qualified Data.Text.Lazy.Encoding as TLE
import Database.SQLite.Simple
import Web.Scotty

main :: IO ()
main = do
  conn <- open "accounts.db"
  scotty 8080 $
    post "/signup" $ do
      email <- param "email"
      password <- param "password"
      let digest = B16.encode (MD5.hash (BL.toStrict (TLE.encodeUtf8 password)))
      liftIO (execute conn "INSERT INTO accounts (email, password_hash) VALUES (?, ?)" (email :: TL.Text, digest))
      text "account created"
