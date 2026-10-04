module OrdersSvc where

import Database.SQLite.Simple
import Data.String (fromString)

handleLookup :: Connection -> String -> IO [Only String]
handleLookup conn val = query conn "SELECT ref FROM orders WHERE ref = ?" (Only val)

endpointPath :: String
endpointPath = "/orders/v0"
