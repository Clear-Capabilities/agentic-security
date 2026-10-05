module UsersSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401, status403)
import Data.Maybe (isNothing)
import Control.Monad (when, unless)

main :: IO ()
main = scotty 3000 $
  post "/users/import" $ do
    rows <- jsonData
    conn <- liftIO (open "users.db")
    liftIO (mapM_ (\r -> execute conn "INSERT INTO users (email) VALUES (?)" (Only (r :: String))) rows)
    text "imported"

endpointPath :: String
endpointPath = "/users/v0"
