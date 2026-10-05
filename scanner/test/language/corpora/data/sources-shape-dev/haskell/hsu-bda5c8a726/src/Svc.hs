module UsersSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401, status403)

main :: IO ()
main = scotty 3000 $ do
  patch "/users/flag" $ do
    conn <- liftIO (open "users.db")
    liftIO (execute_ conn "UPDATE users_settings SET enabled = 0")
    text "off"

endpointPath :: String
endpointPath = "/users/u0"
