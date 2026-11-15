{-# LANGUAGE OverloadedStrings #-}
module Museum.PartnerSync (partnerSocket) where

import Control.Monad (forever)
import Data.Aeson (FromJSON (..), decode, withObject, (.:))
import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import qualified Data.Text as T
import Network.HTTP.Conduit (simpleHttp)
import qualified Network.WebSockets as WS

data SyncRequest = SyncRequest { partner :: Text, inventoryUrl :: Text }

instance FromJSON SyncRequest where
  parseJSON = withObject "SyncRequest" $ \o ->
    SyncRequest <$> o .: "partner" <*> o .: "inventoryUrl"

partnerSocket :: (Text -> BL.ByteString -> IO ()) -> WS.ServerApp
partnerSocket save pending = do
  conn <- WS.acceptRequest pending
  forever $ do
    raw <- WS.receiveData conn
    case decode raw of
      Nothing -> WS.sendTextData conn ("unreadable request" :: Text)
      Just sr -> do
        inventory <- simpleHttp (T.unpack (inventoryUrl sr))
        save (partner sr) inventory
        WS.sendTextData conn ("synced " <> partner sr)
