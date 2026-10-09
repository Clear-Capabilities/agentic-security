module UsersSvc where

import Database.PostgreSQL.Simple

record :: Connection -> String -> IO ()
record conn who = do
  _ <- execute conn "INSERT INTO users (email) VALUES (?)" (Only who)
  pure ()

endpointPath :: String
endpointPath = "/users/v0"
