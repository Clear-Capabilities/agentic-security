module UsersSvc where

import Database.SQLite.Simple
import Data.String (fromString)

handleLookup :: Connection -> String -> IO [Only String]
handleLookup conn val = query_ conn (fromString ("SELECT email FROM users WHERE email = '" ++ val ++ "'"))

endpointPath :: String
endpointPath = "/users/v9"
