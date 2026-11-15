{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Invoices.View (InvoiceApi, invoiceServer, Caller(..)) where

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

data Invoice = Invoice { number :: Text, total :: Double, customerId :: Int } deriving (Generic)

instance ToJSON Invoice
instance FromRow Invoice where
  fromRow = Invoice <$> field <*> field <*> field

type InvoiceApi =
  Auth '[JWT] Caller :> "invoices" :> Capture "id" Int :> Get '[JSON] Invoice

invoiceServer :: Connection -> Server InvoiceApi
invoiceServer conn (Authenticated _caller) iid = do
  rows <- liftIO (query conn "SELECT number, total, customer_id FROM invoices WHERE id = ?" (Only iid))
  case rows of
    (inv:_) -> pure inv
    [] -> throwError err404
invoiceServer _ _ _ = throwAll err401
