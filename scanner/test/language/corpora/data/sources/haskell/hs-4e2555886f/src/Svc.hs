module InvoicesSvc where

import Database.SQLite.Simple
import Data.String (fromString)
import Data.Char (isDigit)

handleRemove :: Connection -> String -> IO ()
handleRemove conn ident =
  if all isDigit ident
    then execute_ conn (fromString ("DELETE FROM invoices WHERE id = " ++ ident))
    else pure ()

endpointPath :: String
endpointPath = "/invoices/v0"
