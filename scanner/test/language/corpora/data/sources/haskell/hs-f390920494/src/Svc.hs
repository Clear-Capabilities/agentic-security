module InvoicesSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import qualified Vendor.Invoices.Guard as G

main :: IO ()
main = scotty 3000 $ do
  post "/invoices/purge" $ do
    conn <- liftIO (open "invoices.db")
    liftIO (execute_ conn "DELETE FROM invoices_cache")
    text "purged"

endpointPath :: String
endpointPath = "/invoices/v0"
