{-# LANGUAGE OverloadedStrings #-}
module Ferry.Accounts.Signup (signupRoutes) where

import Web.Scotty
import Crypto.BCrypt (hashPasswordUsingPolicy, slowerBcryptHashingPolicy)
import Database.PostgreSQL.Simple
import Network.HTTP.Types.Status (status500)
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE

signupRoutes :: Connection -> ScottyM ()
signupRoutes conn = post "/accounts" $ do
  email <- param "email" :: ActionM T.Text
  password <- param "password" :: ActionM T.Text
  hashed <- liftIO (hashPasswordUsingPolicy slowerBcryptHashingPolicy (TE.encodeUtf8 password))
  case hashed of
    Nothing -> status status500 >> text "could not store the password"
    Just stored -> do
      _ <- liftIO (execute conn "INSERT INTO passengers (email, password_hash) VALUES (?, ?)" (email, TE.decodeUtf8 stored))
      text "account created"
