module InvoicesSvc where

import Database.SQLite.Simple
import Data.String (fromString)

handleRemove :: Connection -> String -> IO ()
handleRemove conn ident = execute_ conn (fromString ("DELETE FROM invoices WHERE id = " ++ ident))

endpointPath :: String
endpointPath = "/invoices/v0"
