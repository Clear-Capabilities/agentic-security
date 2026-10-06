module UsersSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401, status403)
import Data.Maybe (isNothing)
import Control.Monad (when, unless)

main :: IO ()
main = scotty 3000 $
  delete "/users/all" $ do
    conn <- liftIO (open "users.db")
    liftIO (execute_ conn "DELETE FROM users")
    text "cleared"

endpointPath :: String
endpointPath = "/users/v0"
