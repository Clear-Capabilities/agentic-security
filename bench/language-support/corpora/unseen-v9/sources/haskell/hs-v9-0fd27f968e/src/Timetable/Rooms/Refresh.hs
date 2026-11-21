{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings, DeriveGeneric #-}
module Timetable.Rooms.Refresh (RefreshAPI, refreshServer) where

import Servant
import qualified Network.Wreq as W
import Control.Lens ((^.), (&), (.~))
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON)
import GHC.Generics (Generic)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text as T

data RefreshRequest = RefreshRequest { buildingApi :: T.Text, term :: T.Text } deriving Generic
instance FromJSON RefreshRequest

type RefreshAPI = "rooms" :> "sync" :> ReqBody '[JSON] RefreshRequest :> Post '[JSON] Int

knownBuildingApis :: [T.Text]
knownBuildingApis =
  [ "https://rooms.north-campus.example"
  , "https://rooms.south-campus.example"
  , "https://rooms.sports-hall.example"
  ]

refreshServer :: Server RefreshAPI
refreshServer req
  | buildingApi req `elem` knownBuildingApis = do
      let opts = W.defaults & W.param "term" .~ [term req]
      r <- liftIO (W.getWith opts (T.unpack (buildingApi req) ++ "/rooms"))
      pure (fromIntegral (BL.length (r ^. W.responseBody)))
  | otherwise = throwError err400 { errBody = "unknown building api" }
