module OrdersSvc where

import Database.SQLite.Simple

lookupBy :: Connection -> String -> IO [Only String]
lookupBy conn who = queryNamed conn "SELECT ref FROM orders WHERE ref = :who" [":who" := who]

endpointPath :: String
endpointPath = "/orders/v0"
