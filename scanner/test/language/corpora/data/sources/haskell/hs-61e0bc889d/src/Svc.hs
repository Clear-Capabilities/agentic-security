module OrdersSvc where

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
  put "/orders/settings" $ do
    requireAuth
    conn <- liftIO (open "orders.db")
    label <- param "label"
    liftIO (execute conn "UPDATE orders_settings SET ref = ?" (Only (label :: String)))
    text "saved"

endpointPath :: String
endpointPath = "/orders/v1"
