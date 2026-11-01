{-# LANGUAGE OverloadedStrings #-}
module HealthCheck (healthSite) where

import Control.Exception (SomeException, try)
import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Char8 as B
import Database.SQLite.Simple
import Snap.Core

healthSite :: Connection -> Snap ()
healthSite conn = route
  [ ("/healthz", method GET (healthHandler conn))
  , ("/version", writeBS "northwind-api 4.12.0")
  ]

healthHandler :: Connection -> Snap ()
healthHandler conn = do
  reachable <- liftIO (databaseReachable conn)
  modifyResponse (setContentType "text/plain")
  if reachable
    then writeBS "ok"
    else modifyResponse (setResponseStatus 503 "database unreachable") >> writeBS "degraded"

databaseReachable :: Connection -> IO Bool
databaseReachable conn = do
  outcome <- try (query_ conn "SELECT 1" :: IO [Only Int]) :: IO (Either SomeException [Only Int])
  pure (either (const False) (not . null) outcome)
