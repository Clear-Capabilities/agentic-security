{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Shipments.Listing (ShipmentApi, shipmentServer) where

import Control.Monad.IO.Class (liftIO)
import Control.Monad.Logger (logInfoN, runStdoutLoggingT)
import Crypto.Hash (SHA256(..), hashWith)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Servant

import Shipments.Store (Shipment, listShipments)
import Tokens (tokenValid)

type ShipmentApi =
  "shipments" :> Header' '[Required] "Authorization" Text :> Get '[JSON] [Shipment]

-- a short identifier for a token that does not reveal the token itself
fingerprint :: Text -> Text
fingerprint = T.take 12 . T.pack . show . hashWith SHA256 . TE.encodeUtf8

shipmentServer :: Server ShipmentApi
shipmentServer authHeader = do
  let token = T.strip (T.replace "Bearer" "" authHeader)
  ok <- liftIO (checkToken token)
  if ok then liftIO listShipments else throwError err401

checkToken :: Text -> IO Bool
checkToken token = runStdoutLoggingT $ do
  logInfoN ("verifying bearer token " <> fingerprint token)
  liftIO (tokenValid token)
