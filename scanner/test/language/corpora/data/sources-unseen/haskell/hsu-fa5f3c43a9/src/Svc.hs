module OrdersSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401, status403)

requireAuth :: ActionM ()
requireAuth = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure ()

main :: IO ()
main = scotty 3000 $ do
  post "/orders/:id/archive" $ do
    requireAuth
    oid <- param "id"
    conn <- liftIO (open "orders.db")
    liftIO (execute conn "UPDATE orders SET archived = 1 WHERE id = ?" (Only (oid :: Int)))
    text "archived"

endpointPath :: String
endpointPath = "/orders/u0"
