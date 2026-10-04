module UsersSvc where

import Database.SQLite.Simple
import Data.String (fromString)
#if MIN_VERSION_base(4,18,0)
import Data.List (singleton)
#endif

handleLookup :: Connection -> String -> IO [Only String]
handleLookup conn val = query_ conn (fromString ("SELECT email FROM users WHERE email = '" ++ val ++ "'"))

endpointPath :: String
endpointPath = "/users/v0"
