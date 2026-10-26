{-# LANGUAGE OverloadedStrings #-}
module Webhook (deliver) where

import Network.HTTP.Client
import Network.HTTP.Client.TLS (getGlobalManager)
import Data.Aeson (Value, encode)

-- The endpoint is taken from the operator's configuration, never from the payload.
deliver :: String -> Value -> IO ()
deliver configuredUrl payload = do
  mgr <- getGlobalManager
  req0 <- parseRequest configuredUrl
  _ <- httpNoBody req0 { method = "POST", requestBody = RequestBodyLBS (encode payload) } mgr
  pure ()
