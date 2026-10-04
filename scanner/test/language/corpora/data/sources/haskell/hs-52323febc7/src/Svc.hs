module InvoicesSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple

main :: IO ()
main = scotty 3000 $ do
  put "/invoices/settings" $ do
    conn <- liftIO (open "invoices.db")
    label <- param "label"
    liftIO (execute conn "UPDATE invoices_settings SET number = ?" (Only (label :: String)))
    text "saved"

endpointPath :: String
endpointPath = "/invoices/v0"
