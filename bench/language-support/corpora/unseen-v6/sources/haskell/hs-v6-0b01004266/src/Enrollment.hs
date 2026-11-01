{-# LANGUAGE OverloadedStrings #-}
module Enrollment (main) where

import Control.Monad.IO.Class (liftIO)
import Crypto.BCrypt (hashPasswordUsingPolicy, slowerBcryptHashingPolicy)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text.Lazy as TL
import qualified Data.Text.Lazy.Encoding as TLE
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status500)
import Web.Scotty

main :: IO ()
main = do
  conn <- open "accounts.db"
  scotty 8080 $
    post "/enroll" $ do
      email <- param "email"
      password <- param "password"
      hashed <- liftIO (hashPasswordUsingPolicy slowerBcryptHashingPolicy (BL.toStrict (TLE.encodeUtf8 password)))
      case hashed of
        Nothing -> status status500 >> text "could not store credentials"
        Just digest -> do
          liftIO (execute conn "INSERT INTO accounts (email, password_hash) VALUES (?, ?)" (email :: TL.Text, digest))
          text "enrolled"
