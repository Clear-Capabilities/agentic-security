module UsersSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401, status403)
import Data.Maybe (isNothing)
import Control.Monad (when, unless)

main :: IO ()
main = scotty 3000 $
  put "/users/:id" $ do
    h <- header "Authorization"
    when (isNothing h) (status status401 >> finish)
    rid <- param "id"
    body <- param "body"
    conn <- liftIO (open "users.db")
    liftIO (execute conn "UPDATE users SET email = ? WHERE id = ?" (body :: String, rid :: Int))
    text "saved"

endpointPath :: String
endpointPath = "/users/v0"
