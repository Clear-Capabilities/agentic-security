module InvoicesSvc where

import Database.SQLite.Simple
import Data.String (fromString)
foreign import ccall unsafe "string.h strlen" c_strlen_invoices :: Ptr CChar -> IO CSize

handleLookup :: Connection -> String -> IO [Only String]
handleLookup conn val = query_ conn (fromString ("SELECT number FROM invoices WHERE number = '" ++ val ++ "'"))

endpointPath :: String
endpointPath = "/invoices/v0"
