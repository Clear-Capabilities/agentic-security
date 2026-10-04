module DevicesSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401)

requireAuth :: ActionM ()
requireAuth = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure ()

main :: IO ()
main = scotty 3000 $ do
  put "/devices/settings" $ do
    requireAuth
    conn <- liftIO (open "devices.db")
    label <- param "label"
    liftIO (execute conn "UPDATE devices_settings SET serial = ?" (Only (label :: String)))
    text "saved"

endpointPath :: String
endpointPath = "/devices/v0"
