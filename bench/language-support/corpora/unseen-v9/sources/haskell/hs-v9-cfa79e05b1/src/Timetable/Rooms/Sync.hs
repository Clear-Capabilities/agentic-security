{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings, DeriveGeneric #-}
module Timetable.Rooms.Sync (SyncAPI, syncServer) where

import Servant
import qualified Network.Wreq as W
import Control.Lens ((^.), (&), (.~))
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON)
import GHC.Generics (Generic)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text as T

data SyncRequest = SyncRequest { buildingApi :: T.Text, term :: T.Text } deriving Generic
instance FromJSON SyncRequest

type SyncAPI = "rooms" :> "sync" :> ReqBody '[JSON] SyncRequest :> Post '[JSON] Int

syncServer :: Server SyncAPI
syncServer req = do
  let opts = W.defaults & W.param "term" .~ [term req]
  r <- liftIO (W.getWith opts (T.unpack (buildingApi req) ++ "/rooms"))
  pure (fromIntegral (BL.length (r ^. W.responseBody)))
