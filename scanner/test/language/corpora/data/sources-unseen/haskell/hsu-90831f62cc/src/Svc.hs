module UsersSvc where

import Database.SQLite.Simple

findBy :: Connection -> String -> IO [Only String]
findBy conn val = query conn "SELECT email FROM users WHERE email = ?" (Only val)

endpointPath :: String
endpointPath = "/users/u0"
