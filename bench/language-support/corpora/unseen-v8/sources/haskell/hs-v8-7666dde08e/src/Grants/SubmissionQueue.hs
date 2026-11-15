{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
module Grants.SubmissionQueue (Submission (..), consumeSubmissions) where

import Control.Monad (void)
import Data.Aeson (FromJSON, eitherDecode)
import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics (Generic)
import Network.AMQP

data Submission = Submission { applicationId :: Int, applicant :: Text, requestedAmount :: Int }
  deriving (Generic, Show)

instance FromJSON Submission

consumeSubmissions :: Channel -> (Submission -> IO ()) -> (Text -> IO ()) -> IO ()
consumeSubmissions chan accept reject =
  void $ consumeMsgs chan "grants.submissions" Ack $ \(msg, env) -> do
    case eitherDecode (msgBody msg) of
      Right s -> accept s
      Left err -> reject (T.pack err)
    ackEnv env
