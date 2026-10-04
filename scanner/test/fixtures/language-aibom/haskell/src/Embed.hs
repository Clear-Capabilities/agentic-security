{-# LANGUAGE OverloadedStrings #-}
module Embed where

import Network.HTTP.Simple
import Data.Aeson (object, (.=))
import qualified Data.Text as T
import Database.PostgreSQL.Simple

embedBody :: T.Text -> Value
embedBody t = object ["model" .= ("text-embedding-3-small" :: T.Text), "input" .= t]

summarise :: T.Text -> IO ()
summarise t = do
  req0 <- parseRequest "https://api.openai.com/v1/embeddings"
  _ <- httpLBS (setRequestBodyJSON (embedBody t) req0)
  _ <- httpLBS (setRequestBodyJSON (object ["model" .= ("gpt-4o-mini" :: T.Text)]) req0)
  pure ()

nearest :: Connection -> [Double] -> IO [Only Int]
nearest conn v = query conn "SELECT id FROM docs ORDER BY embedding <-> ? LIMIT 5" (Only v)
