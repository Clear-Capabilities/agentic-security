{-# LANGUAGE OverloadedStrings #-}
module ToolsSafe where

import Network.HTTP.Simple
import Data.Aeson (object, (.=))

modelUrl :: String
modelUrl = "https://api.openai.com/v1/chat/completions"

modelBody :: String -> Value
modelBody msg = object ["model" .= ("gpt-4o-mini" :: String), "messages" .= [msg]]

dispatch :: String -> String -> String
dispatch tool arg = case tool of
  "get_weather" -> weatherFor arg
  "get_time" -> "12:00"
  _ -> "unknown tool"

weatherFor :: String -> String
weatherFor city = lookupCity city
  where lookupCity c = maybe "unknown" id (lookup c [("paris", "sunny"), ("oslo", "snow")])
