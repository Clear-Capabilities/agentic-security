{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings, DeriveGeneric #-}
module WebhookIntake (IntakeApi, intakeServer) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON, decode)
import qualified Data.ByteString.Lazy as BL
import Data.Maybe (fromJust)
import Data.Text (Text)
import qualified Data.Text.IO as TIO
import GHC.Generics (Generic)
import Servant

data Event = Event { eventType :: Text, eventSubject :: Text }
  deriving (Generic)

instance FromJSON Event

type IntakeApi = "webhooks" :> "intake" :> ReqBody '[OctetStream] BL.ByteString :> Post '[JSON] NoContent

intakeServer :: Server IntakeApi
intakeServer body = do
  let event = parseEvent body
  liftIO (TIO.appendFile "events.log" (eventType event <> " " <> eventSubject event <> "\n"))
  pure NoContent

parseEvent :: BL.ByteString -> Event
parseEvent = fromJust . decode
