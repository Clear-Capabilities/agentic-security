module UsersSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401)

requireUser :: ActionM Int
requireUser = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure 1

main :: IO ()
main = scotty 3000 $ do
  put "/users/:id" $ do
    uid <- requireUser
    rid <- param "id"
    body <- param "body"
    conn <- liftIO (open "users.db")
    liftIO (execute conn "UPDATE users SET email = ? WHERE id = ? AND owner = ?" (body :: String, rid :: Int, uid))
    text "saved"

endpointPath :: String
endpointPath = "/users/v1"
