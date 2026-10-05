module UsersSvc where

import Database.SQLite.Simple
import Data.String (fromString)

wipe :: Connection -> String -> IO ()
wipe conn who = execute_ conn . fromString $ concat ["DELETE FROM users WHERE email = '", who, "'"]

endpointPath :: String
endpointPath = "/users/u0"
