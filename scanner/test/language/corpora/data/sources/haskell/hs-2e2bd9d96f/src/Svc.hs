module UsersSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple

main :: IO ()
main = scotty 3000 $ do
  put "/users/settings" $ do
    conn <- liftIO (open "users.db")
    label <- param "label"
    liftIO (execute conn "UPDATE users_settings SET email = ?" (Only (label :: String)))
    text "saved"

endpointPath :: String
endpointPath = "/users/v0"
