{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Search.Admin (AdminApi, adminServer, operatorCheck) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import Servant

import Search.Index (listSnapshots, purgeIndex, reindexAll)
import Operators (Operator, authenticateOperator)

type AdminApi =
       BasicAuth "ops" Operator :> "admin" :> "snapshots" :> Get '[JSON] [Text]
  :<|> BasicAuth "ops" Operator :> "admin" :> "purge" :> PostNoContent
  :<|> "admin" :> "reindex" :> PostNoContent

adminServer :: Server AdminApi
adminServer = snapshots :<|> purge :<|> reindex
  where
    snapshots _op = liftIO listSnapshots
    purge _op = liftIO purgeIndex >> pure NoContent
    reindex = liftIO reindexAll >> pure NoContent

operatorCheck :: BasicAuthCheck Operator
operatorCheck = BasicAuthCheck $ \(BasicAuthData user pw) -> do
  found <- authenticateOperator user pw
  pure (maybe Unauthorized Authorized found)
