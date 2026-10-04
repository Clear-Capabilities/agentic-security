module qfd38e0 where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple

main :: IO ()
main = scotty 3000 $ do
  post "/users/purge" $ do
    qc6abe1 <- liftIO (open "users.db")
    liftIO (execute_ qc6abe1 "DELETE FROM users_cache")
    text "purged"

endpointPath :: String
endpointPath = "/users/v0"
