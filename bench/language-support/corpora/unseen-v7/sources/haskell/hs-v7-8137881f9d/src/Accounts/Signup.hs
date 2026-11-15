{-# LANGUAGE OverloadedStrings #-}
module Accounts.Signup (signupRoutes) where

import Control.Monad.IO.Class (liftIO)
import Crypto.BCrypt (hashPasswordUsingPolicy, slowerBcryptHashingPolicy)
import Data.Aeson (object, (.=))
import qualified Data.Text.Encoding as TE
import qualified Data.Text.Lazy as TL
import Database.PostgreSQL.Simple
import Network.HTTP.Types.Status (status500)
import Web.Scotty

signupRoutes :: Connection -> ScottyM ()
signupRoutes conn =
  post "/accounts" $ do
    email <- param "email"
    pw <- param "password"
    hashed <- liftIO (hashPasswordUsingPolicy slowerBcryptHashingPolicy (TE.encodeUtf8 (TL.toStrict pw)))
    case hashed of
      Nothing -> status status500 >> text "could not create account"
      Just h -> do
        _ <- liftIO (execute conn "INSERT INTO accounts (email, password_hash) VALUES (?, ?)" (TL.toStrict email, h))
        json (object ["created" .= TL.toStrict email])
