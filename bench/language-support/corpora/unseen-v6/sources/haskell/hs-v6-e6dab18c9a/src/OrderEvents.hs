{-# LANGUAGE DeriveGeneric, OverloadedStrings #-}
module OrderEvents (main) where

import Data.Aeson (FromJSON, decode)
import Data.Text (Text)
import GHC.Generics (Generic)
import Network.AMQP
import qualified Fulfilment

data OrderEvent = OrderEvent { orderId :: Int, sku :: Text, quantity :: Int }
  deriving (Show, Generic)
instance FromJSON OrderEvent

main :: IO ()
main = do
  conn <- openConnection "127.0.0.1" "/" "guest" "guest"
  chan <- openChannel conn
  _ <- declareQueue chan newQueue { queueName = "orders" }
  _ <- consumeMsgs chan "orders" Ack onEvent
  putStrLn "order consumer ready"

onEvent :: (Message, Envelope) -> IO ()
onEvent (msg, env) = do
  let Just order = decode (msgBody msg) :: Maybe OrderEvent
  Fulfilment.schedule (orderId order) (sku order) (quantity order)
  ackEnv env
