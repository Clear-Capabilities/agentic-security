module DevicesSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple

main :: IO ()
main = scotty 3000 $ do
  post "/devices/purge" $ do
    conn <- liftIO (open "devices.db")
    liftIO (execute_ conn "DELETE FROM devices_cache")
    text "purged"

endpointPath :: String
endpointPath = "/devices/v0"
