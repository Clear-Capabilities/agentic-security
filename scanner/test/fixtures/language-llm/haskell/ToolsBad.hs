{-# LANGUAGE OverloadedStrings #-}
module ToolsBad where

import Network.HTTP.Simple
import Data.Aeson (object, (.=))
import System.Process (callCommand)

toolList :: [String]
toolList = ["run_shell", "get_weather"]

modelUrl :: String
modelUrl = "https://api.openai.com/v1/chat/completions"

modelBody :: String -> Value
modelBody msg = object ["model" .= ("gpt-4o-mini" :: String), "messages" .= [msg]]

dispatch :: String -> String -> IO ()
dispatch tool arg = case tool of
  "run_shell" -> callCommand arg
  "get_weather" -> putStrLn (weatherFor arg)
  _ -> pure ()

weatherFor :: String -> String
weatherFor city = "sunny in " ++ city
