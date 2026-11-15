{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Invoices.Detail (InvoiceApi, invoiceServer, Caller(..)) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON, ToJSON)
import Data.Text (Text)
import Database.PostgreSQL.Simple
import GHC.Generics (Generic)
import Servant
import Servant.Auth.Server

data Caller = Caller { callerId :: Int, callerEmail :: Text } deriving (Generic)

instance FromJSON Caller
instance ToJSON Caller
instance FromJWT Caller
instance ToJWT Caller

data Invoice = Invoice { number :: Text, total :: Double } deriving (Generic)

instance ToJSON Invoice
instance FromRow Invoice where
  fromRow = Invoice <$> field <*> field

type InvoiceApi =
  Auth '[JWT] Caller :> "invoices" :> Capture "id" Int :> Get '[JSON] Invoice

invoiceServer :: Connection -> Server InvoiceApi
invoiceServer conn (Authenticated caller) iid = do
  rows <- liftIO (query conn "SELECT number, total FROM invoices WHERE id = ? AND customer_id = ?" (iid, callerId caller))
  case rows of
    (inv:_) -> pure inv
    [] -> throwError err404
invoiceServer _ _ _ = throwAll err401
