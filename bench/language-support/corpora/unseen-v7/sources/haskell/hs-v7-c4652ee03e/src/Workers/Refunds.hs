{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
module Workers.Refunds (onRefundMessage) where

import Data.Aeson (FromJSON, decode)
import Data.Maybe (fromJust)
import Data.Text (Text)
import GHC.Generics (Generic)
import Network.AMQP (Envelope, Message(..), ackEnv)

import Payments (issueRefund)

data Refund = Refund
  { orderRef    :: Text
  , amountCents :: Int
  , reason      :: Text
  } deriving (Generic)

instance FromJSON Refund

onRefundMessage :: (Message, Envelope) -> IO ()
onRefundMessage (msg, env) = do
  let refund = fromJust (decode (msgBody msg))
  issueRefund (orderRef refund) (amountCents refund) (reason refund)
  ackEnv env
