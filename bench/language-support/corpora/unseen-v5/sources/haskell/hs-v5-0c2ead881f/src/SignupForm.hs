{-# LANGUAGE OverloadedStrings #-}
module SignupForm (signupRoutes) where

import Control.Monad.IO.Class (liftIO)
import Crypto.Hash (Digest, MD5, hash)
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
        digest  = hash (accountPassword account) :: Digest MD5
    _ <- liftIO (execute conn "INSERT INTO accounts (email, password_digest) VALUES (?, ?)" (accountEmail account, show digest))
    redirect "/welcome"
