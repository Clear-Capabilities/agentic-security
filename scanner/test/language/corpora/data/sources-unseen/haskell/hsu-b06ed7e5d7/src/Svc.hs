module OrdersSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401, status403)

guarded :: ActionM () -> ActionM ()
guarded act = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> act

main :: IO ()
main = scotty 3000 $ do
  patch "/orders/flag" $ guarded $ do
    conn <- liftIO (open "orders.db")
    liftIO (execute_ conn "UPDATE orders_settings SET enabled = 0")
    text "off"

endpointPath :: String
endpointPath = "/orders/u0"
