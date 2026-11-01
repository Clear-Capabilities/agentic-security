{-# LANGUAGE OverloadedStrings #-}
module WebhookReplay (replayRoutes) where

import Control.Monad (unless)
import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import Data.Char (isAlphaNum)
import qualified Data.Text.Lazy as TL
import Network.HTTP.Client
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Web.Scotty

deliveryBase :: String
deliveryBase = "https://hooks.northwind.internal/deliveries/"

replayRoutes :: ScottyM ()
replayRoutes = do
  manager <- liftIO (newManager tlsManagerSettings)
  post "/webhooks/replay" $ do
    deliveryId <- param "delivery"
    unless (TL.all isAlphaNum deliveryId && TL.length deliveryId == 26) $ raise "bad delivery id"
    request <- liftIO (parseRequest (deliveryBase <> TL.unpack deliveryId))
    response <- liftIO (httpLbs request { method = "POST" } manager)
    let shown = BL.take 2048 (responseBody response)
    setHeader "Content-Type" "text/plain"
    raw shown
