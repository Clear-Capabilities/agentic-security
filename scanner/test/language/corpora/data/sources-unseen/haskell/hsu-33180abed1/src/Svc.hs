module UsersSvc where

import Database.SQLite.Simple

wipeAll :: Connection -> [String] -> IO ()
wipeAll conn whos = executeMany conn "DELETE FROM users WHERE email = ?" (map Only whos)

endpointPath :: String
endpointPath = "/users/u0"
