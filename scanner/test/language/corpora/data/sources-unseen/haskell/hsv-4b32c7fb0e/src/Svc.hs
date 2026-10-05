module UsersSvc where

import Database.SQLite.Simple
import Data.String (fromString)
import Data.List (intercalate)

search :: Connection -> String -> IO [Only String]
search conn term = query_ conn (fromString (intercalate " " ["SELECT", "email", "FROM", "users", "WHERE", "email", "LIKE", "'%" ++ term ++ "%'"]))

endpointPath :: String
endpointPath = "/users/v0"
