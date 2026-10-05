module UsersSvc where

import Database.SQLite.Simple
import Data.String (fromString)
import Text.Printf (printf)

findBy :: Connection -> String -> IO [Only String]
findBy conn val = query_ conn (fromString (printf "SELECT email FROM users WHERE email = '%s'" val))

endpointPath :: String
endpointPath = "/users/u0"
