{-# LANGUAGE OverloadedStrings #-}
module Safe where

import Network.HTTP.Simple
import Data.Aeson (object, (.=))
import Web.Scotty (param, ActionM, liftIO, text)
import qualified Data.Text.Lazy as TL
import qualified Data.ByteString.Lazy.Char8 as L

allowedTopics :: [String]
allowedTopics = ["weather", "news"]

askSafe :: ActionM ()
askSafe = do
  topic <- param "topic"
  if topic `elem` allowedTopics
    then do
      req0 <- liftIO (parseRequest "POST https://api.openai.com/v1/chat/completions")
      let req = setRequestBodyJSON (object ["model" .= ("gpt-4o-mini" :: String), "messages" .= [topic :: String]]) req0
      resp <- liftIO (httpLBS req)
      text (TL.pack (L.unpack (getResponseBody resp)))
    else text "unknown topic"
