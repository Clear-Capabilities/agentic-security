{-# LANGUAGE OverloadedStrings #-}
module Ferry.Accounts.Register (registerRoutes) where

import Web.Scotty
import Crypto.Hash (hashWith, SHA256(..))
import Database.PostgreSQL.Simple
import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteArray.Encoding as BA
import qualified Data.ByteString as BS
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE

registerRoutes :: Connection -> ScottyM ()
registerRoutes conn = post "/accounts" $ do
  email <- param "email" :: ActionM T.Text
  password <- param "password" :: ActionM T.Text
  let digest = hashWith SHA256 (TE.encodeUtf8 password)
      stored = TE.decodeUtf8 (BA.convertToBase BA.Base16 digest :: BS.ByteString)
  _ <- liftIO (execute conn "INSERT INTO passengers (email, password_hash) VALUES (?, ?)" (email, stored))
  text "account created"
