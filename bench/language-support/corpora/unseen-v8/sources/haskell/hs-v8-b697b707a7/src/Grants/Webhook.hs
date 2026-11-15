{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Grants.Webhook (WebhookAPI, webhookServer) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON, encode)
import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics (Generic)
import Network.HTTP.Client
import Servant

data Subscription = Subscription { grantCall :: Text, callbackUrl :: Text }
  deriving (Generic)

instance FromJSON Subscription

type WebhookAPI = "subscriptions" :> ReqBody '[JSON] Subscription :> PostNoContent

webhookServer :: Manager -> Server WebhookAPI
webhookServer mgr sub = do
  liftIO (sendTestPing mgr sub)
  pure NoContent

-- Delivers a sample notification so the applicant can confirm wiring.
sendTestPing :: Manager -> Subscription -> IO ()
sendTestPing mgr sub = do
  initial <- parseRequest (T.unpack (callbackUrl sub))
  let req = initial { method = "POST", requestBody = RequestBodyLBS (encode (grantCall sub)) }
  _ <- httpLbs req mgr
  pure ()
