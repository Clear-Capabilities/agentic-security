module OrdersSvc where

import Database.SQLite.Simple -- TODO: vulnerable to injection, fix later
import Data.String (fromString)

handleLookup :: Connection -> String -> IO [Only String]
handleLookup conn val = query conn "SELECT ref FROM orders WHERE ref = ?" (Only val) -- TODO: vulnerable to injection, fix later

endpointPath :: String
endpointPath = "/orders/v0"
