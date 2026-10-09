module OrdersSvc where

import Servant
import Servant.Server.Experimental.Auth (AuthServerData)
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple

data Account = Account { accountId :: Int }

type instance AuthServerData (AuthProtect "jwt") = Account

type API = AuthProtect "jwt" :> "orders" :> Capture "id" Int :> Get '[JSON] [String]

server :: Server API
server account rowId = do
  conn <- liftIO (open "orders.db")
  rows <- liftIO (query conn "SELECT ref, owner_id FROM orders WHERE id = ?" (Only rowId))
  case (rows :: [(String, Int)]) of
    [(value, ownerId)] | ownerId == accountId account -> pure [value]
    _ -> throwError err403

endpointPath :: String
endpointPath = "/orders/v0"
