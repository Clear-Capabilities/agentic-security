{-# LANGUAGE OverloadedStrings #-}
module InvoiceDetail (invoiceRoutes) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.Text as T
import qualified Data.Text.Lazy as TL
import Database.PostgreSQL.Simple
import Network.HTTP.Types.Status (status401, status404)
import Web.Scotty

data Invoice = Invoice { invoiceNumber :: T.Text, invoiceTotal :: Double, invoicePdf :: T.Text }

instance FromRow Invoice where
  fromRow = Invoice <$> field <*> field <*> field

currentUser :: Connection -> ActionM Int
currentUser conn = do
  token <- header "X-Session"
  rows <- maybe (pure []) (\t -> liftIO (query conn "SELECT user_id FROM sessions WHERE token = ?" (Only (TL.toStrict t)))) token
  case rows of
    (Only uid : _) -> pure uid
    []             -> status status401 >> text "sign in first" >> finish

invoiceRoutes :: Connection -> ScottyM ()
invoiceRoutes conn =
  get "/invoices/:id" $ do
    uid <- currentUser conn
    invoiceId <- param "id"
    rows <- liftIO (query conn "SELECT number, total, pdf_url FROM invoices WHERE id = ? AND owner_id = ?" (invoiceId :: Int, uid))
    case rows of
      (inv : _) -> text (TL.fromStrict (invoiceNumber inv <> " " <> invoicePdf inv))
      []        -> status status404 >> text "no such invoice"
