{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings, TypeFamilies #-}
module Api where

import Servant
import Servant.Auth.Server hiding (BasicAuth)
import Database.PostgreSQL.Simple
import Control.Monad.IO.Class (liftIO)
import Servant.Server.Experimental.Auth (AuthServerData)
data Item = Item { itemName :: String }

type API =
       "health" :> Get '[JSON] String
  :<|> "items" :> ReqBody '[JSON] String :> Post '[JSON] String
  :<|> BasicAuth "items" Int :> "mine" :> Capture "id" Int :> Get '[JSON] String
  :<|> BasicAuth "items" Int :> "theirs" :> Capture "id" Int :> Get '[JSON] String
  :<|> AuthProtect "admin" :> "admin" :> "purge" :> Delete '[JSON] String

server :: Connection -> Server API
server conn = health :<|> addItem :<|> mine :<|> theirs :<|> purge
  where
    health = pure "ok"
    addItem name = liftIO (execute conn "INSERT INTO items (name) VALUES (?)" (Only name)) >> pure "added"
    mine uid i = liftIO (query conn "SELECT name FROM items WHERE id = ? AND owner = ?" (i, uid)) >>= \rows -> pure (show (rows :: [Only String]))
    theirs uid i = liftIO (query conn "SELECT name FROM items WHERE id = ?" (Only i)) >>= \rows -> pure (show (rows :: [Only String]))
    purge _ = liftIO (execute_ conn "DELETE FROM items") >> pure "purged"

type instance AuthServerData (AuthProtect "admin") = ()
