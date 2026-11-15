{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Accounts.Register (RegisterApi, registerServer) where

import Control.Monad.IO.Class (liftIO)
import Crypto.Hash (SHA256(..), hashWith)
import Data.Aeson (FromJSON)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Database.PostgreSQL.Simple
import GHC.Generics (Generic)
import Servant

data Registration = Registration
  { email    :: Text
  , password :: Text
  } deriving (Generic)

instance FromJSON Registration

type RegisterApi = "accounts" :> ReqBody '[JSON] Registration :> PostNoContent

registerServer :: Connection -> Server RegisterApi
registerServer conn reg = do
  _ <- liftIO (execute conn "INSERT INTO accounts (email, password_hash) VALUES (?, ?)" (email reg, storedHash (password reg)))
  pure NoContent

storedHash :: Text -> Text
storedHash pw = T.pack (show (hashWith SHA256 (TE.encodeUtf8 pw)))
