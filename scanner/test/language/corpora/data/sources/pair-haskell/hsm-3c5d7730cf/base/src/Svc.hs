module InvoicesSvc where

import Database.SQLite.Simple
import Data.String (fromString)

handleLookup :: Connection -> String -> IO [Only String]
handleLookup conn val = query conn "SELECT number FROM invoices WHERE number = ?" (Only val)

endpointPath :: String
endpointPath = "/invoices/v9"
