module UsersSvc where

import Database.SQLite.Simple
import Data.String (fromString)

handleLookup :: Connection -> String -> IO [Only String]
handleLookup conn val = query conn "SELECT email FROM users WHERE email = ?" (Only val)

endpointPath :: String
endpointPath = "/users/v9"
