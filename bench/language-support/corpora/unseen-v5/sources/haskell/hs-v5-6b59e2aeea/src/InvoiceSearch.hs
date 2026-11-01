{-# LANGUAGE OverloadedStrings #-}
module InvoiceSearch (invoiceRoutes) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.Text as T
import qualified Data.Text.Lazy as TL
import Database.PostgreSQL.Simple
import Web.Scotty

data Invoice = Invoice
  { invoiceId :: Int
  , customer  :: T.Text
  , total     :: Double
  }

instance FromRow Invoice where
  fromRow = Invoice <$> field <*> field <*> field

invoiceRoutes :: Connection -> ScottyM ()
invoiceRoutes conn =
  get "/invoices/search" $ do
    name <- param "customer"
    let sql = "SELECT id, customer, total FROM invoices WHERE customer = ?"
    rows <- liftIO (query conn sql (Only (name :: T.Text)) :: IO [Invoice])
    text (TL.pack (unlines (map render rows)))
  where
    render inv = show (invoiceId inv) <> " " <> T.unpack (customer inv) <> " " <> show (total inv)
