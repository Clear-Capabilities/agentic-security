{-# LANGUAGE OverloadedStrings #-}
module Handler where

import Types
import qualified Store
import qualified Audit
import qualified Outbound
import Web.Scotty (ActionM, jsonData, text, liftIO)
import Database.PostgreSQL.Simple (Connection)

signup :: Connection -> ActionM ()
signup conn = do
  s <- jsonData
  liftIO (Store.persist conn s)
  liftIO (Audit.record s)
  liftIO (Outbound.syncCrm s)
  liftIO (Outbound.pingAnalytics s)
  liftIO (Outbound.welcome s)
  liftIO (Outbound.enqueue s)
  liftIO (Outbound.spill s)
  text (nickname s)
