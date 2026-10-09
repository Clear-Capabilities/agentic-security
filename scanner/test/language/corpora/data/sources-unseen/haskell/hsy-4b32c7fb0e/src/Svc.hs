module UsersSvc where

import Database.MySQL.Simple
import Data.String (fromString)
import Text.Printf (printf)

searchBy :: Connection -> String -> IO [Only String]
searchBy conn term = query_ conn (fromString (printf "SELECT email FROM users WHERE email LIKE '%%%s%%'" term))

endpointPath :: String
endpointPath = "/users/v0"
