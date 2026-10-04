{-# LANGUAGE OverloadedStrings #-}
module NoAI where

-- we might use https://api.openai.com/v1/chat/completions with "model" = "gpt-4o" some day
note :: String
note = "openai is only mentioned in a log message"

car :: [(String, String)]
car = [("model", "sedan"), ("make", "acme")]
