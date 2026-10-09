module UsersSvc where

import Servant
import Servant.Server.Experimental.Auth (AuthServerData)
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple

data Account = Account { accountId :: Int }

type instance AuthServerData (AuthProtect "jwt") = Account

type API = AuthProtect "jwt" :> "users" :> Capture "id" Int :> Get '[JSON] [String]

server :: Server API
server account rowId = do
  conn <- liftIO (open "users.db")
  rows <- liftIO (query conn "SELECT email, owner_id FROM users WHERE id = ?" (Only rowId))
  case (rows :: [(String, Int)]) of
    [(value, ownerId)] | ownerId == accountId account -> pure [value]
    _ -> throwError err403

endpointPath :: String
endpointPath = "/users/v0"
