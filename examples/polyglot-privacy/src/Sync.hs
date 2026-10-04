{-# LANGUAGE OverloadedStrings #-}
module Sync (Customer (..), logSignup, forwardToCrm, summarizeNote) where

import Data.Aeson (object, (.=))
import Network.HTTP.Simple (httpLBS, parseRequest, parseRequest_, setRequestBodyJSON, setRequestBodyLBS)
import qualified Data.ByteString.Lazy.Char8 as L
import qualified Data.Text as T

data Customer = Customer
  { email :: String
  , socialSecurityNumber :: String
  , plan :: String
  }

-- | Writes a signup line to the application log.
logSignup :: Customer -> IO ()
logSignup c = putStrLn ("signup " ++ email c ++ " ssn=" ++ socialSecurityNumber c)

-- | Sends the customer to an external CRM.
forwardToCrm :: Customer -> IO ()
forwardToCrm c = do
  _ <- httpLBS (setRequestBodyLBS (L.pack (email c)) (parseRequest_ "POST https://crm.example.invalid/contacts"))
  pure ()

-- | Asks a hosted model to summarise a free-text support note; the customer's raw text is the prompt.
summarizeNote :: T.Text -> IO ()
summarizeNote note = do
  req0 <- parseRequest "POST https://api.openai.com/v1/chat/completions"
  let body = object ["model" .= ("gpt-4o-mini" :: T.Text), "messages" .= [T.append "Summarise: " note]]
  _ <- httpLBS (setRequestBodyJSON body req0)
  pure ()
