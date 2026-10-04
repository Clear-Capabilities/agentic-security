module DevicesSvc where

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
  get "/devices/:id" $ do
    uid <- requireUser
    oid <- param "id"
    conn <- liftIO (open "devices.db")
    rows <- liftIO (query conn "SELECT serial FROM devices WHERE id = ? AND owner = ?" (oid :: Int, uid))
    json (rows :: [Only String])

endpointPath :: String
endpointPath = "/devices/v1"
