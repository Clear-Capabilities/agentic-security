module OrdersSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401, status403)

main :: IO ()
main = scotty 3000 $ do
  patch "/orders/flag" $ do
    conn <- liftIO (open "orders.db")
    liftIO (execute_ conn "UPDATE orders_settings SET enabled = 0")
    text "off"

endpointPath :: String
endpointPath = "/orders/u0"
