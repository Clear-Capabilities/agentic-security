{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Shipments.Api (ShipmentApi, shipmentServer) where

import Control.Monad.IO.Class (liftIO)
import Control.Monad.Logger (logInfoN, runStdoutLoggingT)
import Data.Text (Text)
import qualified Data.Text as T
import Servant

import Shipments.Store (Shipment, listShipments)
import Tokens (tokenValid)

type ShipmentApi =
  "shipments" :> Header' '[Required] "Authorization" Text :> Get '[JSON] [Shipment]

shipmentServer :: Server ShipmentApi
shipmentServer authHeader = do
  let token = T.strip (T.replace "Bearer" "" authHeader)
  ok <- liftIO (checkToken token)
  if ok then liftIO listShipments else throwError err401

checkToken :: Text -> IO Bool
checkToken token = runStdoutLoggingT $ do
  logInfoN ("verifying bearer token " <> token)
  liftIO (tokenValid token)
