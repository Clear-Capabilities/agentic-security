{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings, DeriveGeneric #-}
module WebhookReceiver (ReceiverApi, receiverServer) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON, eitherDecode)
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Lazy.Char8 as BLC
import Data.Text (Text)
import qualified Data.Text.IO as TIO
import GHC.Generics (Generic)
import Servant

data Event = Event { eventType :: Text, eventSubject :: Text }
  deriving (Generic)

instance FromJSON Event

type ReceiverApi = "webhooks" :> "receive" :> ReqBody '[OctetStream] BL.ByteString :> Post '[JSON] NoContent

receiverServer :: Server ReceiverApi
receiverServer body =
  case parseEvent body of
    Left problem -> throwError err400 { errBody = BLC.pack problem }
    Right event -> do
      liftIO (TIO.appendFile "events.log" (eventType event <> " " <> eventSubject event <> "\n"))
      pure NoContent

parseEvent :: BL.ByteString -> Either String Event
parseEvent = eitherDecode
