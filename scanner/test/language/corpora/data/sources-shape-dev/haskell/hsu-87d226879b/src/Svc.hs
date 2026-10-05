module OrdersSvc where

import Database.SQLite.Simple

wipeAll :: Connection -> [String] -> IO ()
wipeAll conn whos = executeMany conn "DELETE FROM orders WHERE ref = ?" (map Only whos)

endpointPath :: String
endpointPath = "/orders/u0"
