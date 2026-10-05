module OrdersSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401, status403)

requireUser :: ActionM Int
requireUser = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure 1

main :: IO ()
main = scotty 3000 $ do
  delete "/orders/:id" $ do
    uid <- requireUser
    oid <- param "id"
    conn <- liftIO (open "orders.db")
    liftIO (execute conn "DELETE FROM orders WHERE id = ? AND owner = ?" (oid :: Int, uid))
    text "gone"

endpointPath :: String
endpointPath = "/orders/u0"
