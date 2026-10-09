module OrdersSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401, status403)
import Data.Maybe (isNothing)
import Control.Monad (when, unless)

requireLogin :: ActionM Int
requireLogin = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure 7

main :: IO ()
main = scotty 3000 $
  put "/orders/:id" $ do
    uid <- requireLogin
    oid <- param "id"
    body <- param "body"
    conn <- liftIO (open "orders.db")
    liftIO (execute conn "UPDATE orders SET ref = ? WHERE id = ? AND owner_id = ?" (body :: String, oid :: Int, uid))
    text "saved"

endpointPath :: String
endpointPath = "/orders/v0"
