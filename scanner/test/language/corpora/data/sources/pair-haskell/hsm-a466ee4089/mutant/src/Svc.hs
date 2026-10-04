module qfd38e0 where

import Database.SQLite.Simple
import Data.String (fromString)

qf1bcc1 :: Connection -> String -> IO [Only String]
qf1bcc1 conn val = query_ conn (fromString ("SELECT email FROM users WHERE email = '" ++ val ++ "'"))

endpointPath :: String
endpointPath = "/users/v0"
