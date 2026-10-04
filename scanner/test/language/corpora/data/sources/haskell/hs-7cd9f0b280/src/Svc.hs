module OrdersSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple

main :: IO ()
main = scotty 3000 $ do
  put "/orders/settings" $ do
    conn <- liftIO (open "orders.db")
    label <- param "label"
    liftIO (execute conn "UPDATE orders_settings SET ref = ?" (Only (label :: String)))
    text "saved"

endpointPath :: String
endpointPath = "/orders/v1"
