module OrdersSvc where

import Database.MySQL.Simple
import Data.String (fromString)
import Text.Printf (printf)

searchBy :: Connection -> String -> IO [Only String]
searchBy conn term = query_ conn (fromString (printf "SELECT ref FROM orders WHERE ref LIKE '%%%s%%'" term))

endpointPath :: String
endpointPath = "/orders/v0"
