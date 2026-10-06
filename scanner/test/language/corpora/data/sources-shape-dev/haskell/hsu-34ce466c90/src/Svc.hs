module OrdersSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401, status403)

main :: IO ()
main = scotty 3000 $ do
  delete "/orders/:id" $ do
    rid <- param "id"
    conn <- liftIO (open "orders.db")
    liftIO (execute conn "DELETE FROM orders WHERE id = ?" (Only (rid :: Int)))
    text "gone"

endpointPath :: String
endpointPath = "/orders/u0"
