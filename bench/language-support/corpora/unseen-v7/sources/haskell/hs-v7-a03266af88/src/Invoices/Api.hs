{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Invoices.Api (InvoiceApi, invoiceServer) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import Database.PostgreSQL.Simple
import Servant

data InvoiceRow = InvoiceRow Int Text Double

instance FromRow InvoiceRow where
  fromRow = InvoiceRow <$> field <*> field <*> field

type InvoiceApi =
  "invoices" :> QueryParam' '[Required] "customer" Text :> Get '[JSON] [(Int, Text, Double)]

invoiceServer :: Connection -> Server InvoiceApi
invoiceServer conn customer = do
  rows <- liftIO (byCustomer conn customer)
  pure [ (i, n, t) | InvoiceRow i n t <- rows ]

byCustomer :: Connection -> Text -> IO [InvoiceRow]
byCustomer conn customer =
  query conn "SELECT id, number, total FROM invoices WHERE customer_code = ? ORDER BY issued_at DESC" (Only customer)
