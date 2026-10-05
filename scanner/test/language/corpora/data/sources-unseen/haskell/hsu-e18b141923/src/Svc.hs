module OrdersSvc where

import Database.SQLite.Simple

page :: Connection -> String -> Int -> IO [Only String]
page conn val lim = query conn "SELECT ref FROM orders WHERE ref = ? LIMIT ?" (val, lim)

endpointPath :: String
endpointPath = "/orders/u0"
