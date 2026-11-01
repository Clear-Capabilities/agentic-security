{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings, TypeFamilies #-}
module DocumentRemove (RemoveApi, removeServer) where

import Control.Monad.IO.Class (liftIO)
import Data.Int (Int64)
import Database.Persist
import Database.Persist.Sql (ConnectionPool, runSqlPool, toSqlKey)
import Servant
import Servant.Server.Experimental.Auth (AuthServerData)
import Model

type instance AuthServerData (AuthProtect "session") = UserId

type RemoveApi = AuthProtect "session" :> "documents" :> Capture "document" Int64 :> Delete '[JSON] NoContent

removeServer :: ConnectionPool -> Server RemoveApi
removeServer pool requester documentId = do
  removed <- liftIO (removeDocument pool requester (toSqlKey documentId))
  if removed then pure NoContent else throwError err404

removeDocument :: ConnectionPool -> UserId -> DocumentId -> IO Bool
removeDocument pool requester key = flip runSqlPool pool $ do
  owned <- selectFirst [DocumentId ==. key, DocumentOwner ==. requester] []
  case owned of
    Nothing -> pure False
    Just (Entity k _) -> delete k >> pure True
