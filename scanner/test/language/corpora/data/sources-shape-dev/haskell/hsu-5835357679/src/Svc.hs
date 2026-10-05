module UsersSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401, status403)

requireAuth :: ActionM ()
requireAuth = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure ()

main :: IO ()
main = scotty 3000 $ do
  delete "/users/:id" $ do
    requireAuth
    rid <- param "id"
    conn <- liftIO (open "users.db")
    liftIO (execute conn "DELETE FROM users WHERE id = ?" (Only (rid :: Int)))
    text "gone"

endpointPath :: String
endpointPath = "/users/u0"
