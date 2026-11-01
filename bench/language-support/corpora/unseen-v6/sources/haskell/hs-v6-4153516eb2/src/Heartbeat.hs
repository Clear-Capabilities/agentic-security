{-# LANGUAGE OverloadedStrings #-}
module Heartbeat (main) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (encode, object, (.=))
import Data.Text (Text)
import Snap.Core
import Snap.Http.Server (quickHttpServe)
import qualified Status

main :: IO ()
main = quickHttpServe $ route
  [ ("healthz", method GET healthHandler)
  , ("version", method GET versionHandler)
  ]

healthHandler :: Snap ()
healthHandler = do
  reachable <- liftIO Status.databaseReachable
  modifyResponse (setContentType "application/json")
  writeLBS (encode (object ["status" .= (if reachable then "ok" else "degraded" :: Text)]))

versionHandler :: Snap ()
versionHandler = do
  modifyResponse (setContentType "text/plain")
  writeBS "heartbeat 2.4.1"
