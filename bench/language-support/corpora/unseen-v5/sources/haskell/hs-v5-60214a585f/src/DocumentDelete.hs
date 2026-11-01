{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings, TypeFamilies #-}
module DocumentDelete (DeleteApi, deleteServer) where

import Control.Monad.IO.Class (liftIO)
import Data.Int (Int64)
import Database.Persist
import Database.Persist.Sql (ConnectionPool, runSqlPool, toSqlKey)
import Servant
import Servant.Server.Experimental.Auth (AuthServerData)
import Model

type instance AuthServerData (AuthProtect "session") = UserId

type DeleteApi = AuthProtect "session" :> "documents" :> Capture "document" Int64 :> Delete '[JSON] NoContent

deleteServer :: ConnectionPool -> Server DeleteApi
deleteServer pool requester documentId = do
  removed <- liftIO (removeDocument pool requester (toSqlKey documentId))
  if removed then pure NoContent else throwError err404

removeDocument :: ConnectionPool -> UserId -> DocumentId -> IO Bool
removeDocument pool _requester key = flip runSqlPool pool $ do
  existing <- get key
  case existing of
    Nothing -> pure False
    Just _  -> delete key >> pure True
