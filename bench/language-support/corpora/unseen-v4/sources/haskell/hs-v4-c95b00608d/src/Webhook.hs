{-# LANGUAGE OverloadedStrings #-}
module Webhook (deliver) where

import Network.HTTP.Client
import Network.HTTP.Client.TLS (getGlobalManager)
import Data.Aeson (Value, encode)
import Data.Aeson.Types (parseMaybe, (.:))
import qualified Data.Text as T

-- The subscriber chose the callback URL when registering.
deliver :: Value -> Value -> IO ()
deliver subscription payload = do
  mgr <- getGlobalManager
  let Just target = parseMaybe (.: "callback") subscription :: Maybe String
  req0 <- parseRequest target
  _ <- httpNoBody req0 { method = "POST", requestBody = RequestBodyLBS (encode payload) } mgr
  pure ()
