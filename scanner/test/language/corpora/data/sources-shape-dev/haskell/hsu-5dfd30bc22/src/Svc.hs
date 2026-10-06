module UsersSvc where

import Database.SQLite.Simple

page :: Connection -> String -> Int -> IO [Only String]
page conn val lim = query conn "SELECT email FROM users WHERE email = ? LIMIT ?" (val, lim)

endpointPath :: String
endpointPath = "/users/u0"
