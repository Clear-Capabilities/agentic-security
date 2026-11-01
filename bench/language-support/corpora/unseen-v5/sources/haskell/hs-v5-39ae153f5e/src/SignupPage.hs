{-# LANGUAGE OverloadedStrings #-}
module SignupPage (signupRoutes) where

import Control.Monad.IO.Class (liftIO)
import Crypto.BCrypt (hashPasswordUsingPolicy, slowerBcryptHashingPolicy)
import qualified Data.ByteString.Char8 as B
import qualified Data.Text as T
import Database.PostgreSQL.Simple
import Web.Scotty

data NewAccount = NewAccount { accountEmail :: T.Text, accountPassword :: B.ByteString }

signupRoutes :: Connection -> ScottyM ()
signupRoutes conn =
  post "/signup" $ do
    email    <- param "email"
    password <- param "password"
    let account = NewAccount email (B.pack password)
    hashed <- liftIO (hashPasswordUsingPolicy slowerBcryptHashingPolicy (accountPassword account))
    case hashed of
      Nothing -> raise "could not store credentials"
      Just digest -> do
        _ <- liftIO (execute conn "INSERT INTO accounts (email, password_digest) VALUES (?, ?)" (accountEmail account, digest))
        redirect "/welcome"
