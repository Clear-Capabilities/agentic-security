module OrdersSvc where

import Servant
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple

data Admin = Admin

type API = BasicAuth "admin" Admin :> "purge" :> Delete '[JSON] NoContent

server :: Server API
server _admin = do
  conn <- liftIO (open "orders.db")
  liftIO (execute_ conn "DELETE FROM orders")
  pure NoContent

endpointPath :: String
endpointPath = "/orders/v0"
