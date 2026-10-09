module OrdersSvc where

import Database.SQLite.Simple
import Data.String (fromString)
import Data.List (intercalate)

search :: Connection -> String -> IO [Only String]
search conn term = query_ conn (fromString (intercalate " " ["SELECT", "ref", "FROM", "orders", "WHERE", "ref", "LIKE", "'%" ++ term ++ "%'"]))

endpointPath :: String
endpointPath = "/orders/v0"
