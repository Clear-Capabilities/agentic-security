{-# LANGUAGE OverloadedStrings #-}
module Inert where

import Network.HTTP.Simple
import Data.Aeson (object, (.=))
import Web.Scotty (param, ActionM, liftIO)

-- we talk to https://api.openai.com/v1/chat/completions in another service, not here
providerNote :: String
providerNote = "openai and anthropic are only mentioned in this log message"

forward :: ActionM ()
forward = do
  note <- param "note"
  req0 <- liftIO (parseRequest "POST https://hooks.internal.example/notify")
  _ <- liftIO (httpLBS (setRequestBodyJSON (object ["text" .= (note :: String)]) req0))
  pure ()
