module OrdersSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401, status403)
import Data.Maybe (isNothing)
import Control.Monad (when, unless)

main :: IO ()
main = scotty 3000 $
  put "/orders/:id" $ do
    rid <- param "id"
    body <- param "body"
    conn <- liftIO (open "orders.db")
    liftIO (execute conn "UPDATE orders SET ref = ? WHERE id = ?" (body :: String, rid :: Int))
    text "saved"

endpointPath :: String
endpointPath = "/orders/v0"
