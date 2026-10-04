{-# LANGUAGE OverloadedStrings #-}
module Chat where

import Network.HTTP.Simple
import Data.Aeson (object, (.=))
import qualified Data.Text as T

systemPrompt :: T.Text
systemPrompt = "You are a helpful assistant. Answer the user's question about {{topic}} using only the context provided below."

chat :: T.Text -> IO ()
chat msg = do
  req0 <- parseRequest "POST https://api.openai.com/v1/chat/completions?api_key=CANARYQUERYKEY123"
  let body = object ["model" .= ("gpt-4o-mini" :: T.Text), "messages" .= [msg]]
      req = setRequestHeader "Authorization" ["Bearer CANARY-HEADER-TOKEN-9z"] (setRequestBodyJSON body req0)
  _ <- httpLBS req
  pure ()
