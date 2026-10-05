module OrdersSvc where

import Database.SQLite.Simple
import Data.String (fromString)
import Text.Printf (printf)

findBy :: Connection -> String -> IO [Only String]
findBy conn val = query_ conn (fromString (printf "SELECT ref FROM orders WHERE ref = '%s'" val))

endpointPath :: String
endpointPath = "/orders/u0"
