module OrdersSvc where

import Database.PostgreSQL.Simple

record :: Connection -> String -> IO ()
record conn who = do
  _ <- execute conn "INSERT INTO orders (ref) VALUES (?)" (Only who)
  pure ()

endpointPath :: String
endpointPath = "/orders/v0"
