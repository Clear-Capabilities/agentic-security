module UsersSvc where

import Database.SQLite.Simple

lookupBy :: Connection -> String -> IO [Only String]
lookupBy conn who = queryNamed conn "SELECT email FROM users WHERE email = :who" [":who" := who]

endpointPath :: String
endpointPath = "/users/v0"
