{-# LANGUAGE DeriveGeneric, OverloadedStrings #-}
module WebhookDispatch (main) where

import Data.Aeson (FromJSON, decode)
import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics (Generic)
import Network.AMQP
import System.Log.Logger (Priority(..), infoM, setLevel, updateGlobalLogger)
import qualified Delivery

data DispatchJob = DispatchJob { subscriberId :: Int, apiToken :: Text, eventId :: Int }
  deriving (Show, Generic)
instance FromJSON DispatchJob

main :: IO ()
main = do
  updateGlobalLogger "dispatch" (setLevel INFO)
  conn <- openConnection "127.0.0.1" "/" "guest" "guest"
  chan <- openChannel conn
  _ <- declareQueue chan newQueue { queueName = "webhook-dispatch" }
  _ <- consumeMsgs chan "webhook-dispatch" Ack onJob
  putStrLn "dispatcher ready"

onJob :: (Message, Envelope) -> IO ()
onJob (msg, env) = do
  case decode (msgBody msg) of
    Just job -> do
      infoM "dispatch" ("dispatching event " ++ show (eventId job) ++ " to subscriber " ++ show (subscriberId job) ++ " with token " ++ T.unpack (apiToken job))
      Delivery.send (subscriberId job) (apiToken job) (eventId job)
    Nothing -> infoM "dispatch" "skipping a job that did not decode"
  ackEnv env
