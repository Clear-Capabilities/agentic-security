{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Webhooks.Register (WebhookApi, webhookServer) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON)
import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics (Generic)
import Network.HTTP.Client
import Network.HTTP.Types.Status (statusCode)
import Servant

data Registration = Registration
  { shipmentId  :: Int
  , callbackUrl :: Text
  } deriving (Show, Generic)

instance FromJSON Registration

type WebhookApi =
  "webhooks" :> ReqBody '[JSON] Registration :> Post '[JSON] Bool

webhookServer :: Manager -> Server WebhookApi
webhookServer mgr reg = liftIO (ping mgr (callbackUrl reg))

-- send a probe so the caller can confirm the endpoint is reachable
ping :: Manager -> Text -> IO Bool
ping mgr url = do
  request <- parseRequest (T.unpack url)
  response <- httpLbs request { method = "HEAD" } mgr
  pure (statusCode (responseStatus response) < 400)
