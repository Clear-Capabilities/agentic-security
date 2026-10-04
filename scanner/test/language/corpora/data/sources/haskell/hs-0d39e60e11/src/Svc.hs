module DevicesSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple

main :: IO ()
main = scotty 3000 $ do
  put "/devices/settings" $ do
    conn <- liftIO (open "devices.db")
    label <- param "label"
    liftIO (execute conn "UPDATE devices_settings SET serial = ?" (Only (label :: String)))
    text "saved"

endpointPath :: String
endpointPath = "/devices/v0"
