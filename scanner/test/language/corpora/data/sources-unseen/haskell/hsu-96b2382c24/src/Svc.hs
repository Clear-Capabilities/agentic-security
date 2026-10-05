module OrdersSvc where

import Database.SQLite.Simple

findBy :: Connection -> String -> IO [Only String]
findBy conn val = query conn "SELECT ref FROM orders WHERE ref = ?" (Only val)

endpointPath :: String
endpointPath = "/orders/u0"
