{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
module Workers.Credits (onCreditMessage) where

import Data.Aeson (FromJSON, eitherDecode)
import Data.Text (Text)
import GHC.Generics (Generic)
import Network.AMQP (Envelope, Message(..), ackEnv, rejectEnv)

import Payments (issueCredit)

data Credit = Credit
  { orderRef    :: Text
  , amountCents :: Int
  , reason      :: Text
  } deriving (Generic)

instance FromJSON Credit

onCreditMessage :: (Message, Envelope) -> IO ()
onCreditMessage (msg, env) =
  case eitherDecode (msgBody msg) of
    Left err -> do
      putStrLn ("credit message not understood: " ++ err)
      rejectEnv env False
    Right credit -> do
      issueCredit (orderRef credit) (amountCents credit) (reason credit)
      ackEnv env
