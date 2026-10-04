{-# LANGUAGE OverloadedStrings #-}
module Agent where

import Network.HTTP.Simple
import Data.Aeson (object, (.=))
import System.Process (callCommand)
import qualified Data.ByteString.Lazy.Char8 as L
import Web.Scotty (param, ActionM, liftIO)

ask :: ActionM ()
ask = do
  q <- param "q"
  req0 <- liftIO (parseRequest "POST https://api.openai.com/v1/chat/completions")
  let req = setRequestBodyJSON (object ["model" .= ("gpt-4o-mini" :: String), "messages" .= [q :: String]]) req0
  resp <- liftIO (httpLBS req)
  let out = L.unpack (getResponseBody resp)
  liftIO (callCommand out)
