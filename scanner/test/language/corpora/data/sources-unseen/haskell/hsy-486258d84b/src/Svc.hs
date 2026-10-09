module UsersSvc where

import Servant
import Servant.Server.Experimental.Auth (AuthServerData)
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple

data Account = Account { accountId :: Int }

type instance AuthServerData (AuthProtect "jwt") = Account

type API = AuthProtect "jwt" :> "users" :> Capture "id" Int :> Get '[JSON] [String]

server :: Server API
server _account rowId = do
  conn <- liftIO (open "users.db")
  rows <- liftIO (query conn "SELECT email FROM users WHERE id = ?" (Only rowId))
  pure (map fromOnly rows)

endpointPath :: String
endpointPath = "/users/v0"
