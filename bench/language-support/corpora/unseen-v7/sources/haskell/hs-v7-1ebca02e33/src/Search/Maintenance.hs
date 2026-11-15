{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Search.Maintenance (MaintenanceApi, maintenanceServer, operatorCheck) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import Servant

import Search.Index (listSnapshots, purgeIndex, reindexAll)
import Operators (Operator, authenticateOperator)

type MaintenanceApi =
       BasicAuth "ops" Operator :> "admin" :> "snapshots" :> Get '[JSON] [Text]
  :<|> BasicAuth "ops" Operator :> "admin" :> "purge" :> PostNoContent
  :<|> BasicAuth "ops" Operator :> "admin" :> "reindex" :> PostNoContent

maintenanceServer :: Server MaintenanceApi
maintenanceServer = snapshots :<|> purge :<|> reindex
  where
    snapshots _op = liftIO listSnapshots
    purge _op = liftIO purgeIndex >> pure NoContent
    reindex _op = liftIO reindexAll >> pure NoContent

operatorCheck :: BasicAuthCheck Operator
operatorCheck = BasicAuthCheck $ \(BasicAuthData user pw) -> do
  found <- authenticateOperator user pw
  pure (maybe Unauthorized Authorized found)
