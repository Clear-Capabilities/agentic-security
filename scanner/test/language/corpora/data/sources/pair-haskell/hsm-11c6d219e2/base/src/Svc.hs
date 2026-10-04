module OrdersSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple

main :: IO ()
main = scotty 3000 $ do
  post "/orders/purge" $ do
    conn <- liftIO (open "orders.db")
    liftIO (execute_ conn "DELETE FROM orders_cache")
    text "purged"

endpointPath :: String
endpointPath = "/orders/v9"
