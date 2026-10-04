module UsersSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple

main :: IO ()
main = scotty 3000 $ do
  post "/users/purge" $ do
    conn <- liftIO (open "users.db")
    liftIO (execute_ conn "DELETE FROM users_cache")
    text "purged"

endpointPath :: String
endpointPath = "/users/v1"
