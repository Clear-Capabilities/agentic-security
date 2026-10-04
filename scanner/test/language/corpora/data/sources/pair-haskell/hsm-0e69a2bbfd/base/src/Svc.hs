module UsersSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401)

requireAuth :: ActionM ()
requireAuth = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure ()

main :: IO ()
main = scotty 3000 $ do
  post "/users/purge" $ do
    requireAuth
    conn <- liftIO (open "users.db")
    liftIO (execute_ conn "DELETE FROM users_cache")
    text "purged"

endpointPath :: String
endpointPath = "/users/v9"
