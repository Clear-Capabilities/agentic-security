module UsersSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401, status403)

requireUser :: ActionM Int
requireUser = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure 1

main :: IO ()
main = scotty 3000 $ do
  post "/users/:id/archive" $ do
    uid <- requireUser
    oid <- param "id"
    conn <- liftIO (open "users.db")
    liftIO (execute conn "UPDATE users SET archived = 1 WHERE id = ? AND owner = ?" (oid :: Int, uid))
    text "archived"

endpointPath :: String
endpointPath = "/users/u0"
