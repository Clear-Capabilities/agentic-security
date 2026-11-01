{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings, DeriveGeneric #-}
module RegionStatus (RegionApi, regionServer) where

import Control.Lens ((^.))
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Map.Strict as M
import Data.Text (Text)
import GHC.Generics (Generic)
import Network.Wreq (get, responseBody)
import Servant

newtype RegionPick = RegionPick { region :: Text }
  deriving (Generic)

instance FromJSON RegionPick

regionHosts :: M.Map Text String
regionHosts = M.fromList
  [ ("eu-west", "status-eu.northwind.internal")
  , ("us-east", "status-us.northwind.internal")
  , ("ap-south", "status-ap.northwind.internal")
  ]

type RegionApi = "status" :> ReqBody '[JSON] RegionPick :> Post '[OctetStream] BL.ByteString

regionServer :: Server RegionApi
regionServer pick =
  case M.lookup (region pick) regionHosts of
    Nothing   -> throwError err400 { errBody = "unknown region" }
    Just host -> liftIO (fetchStatus host)

fetchStatus :: String -> IO BL.ByteString
fetchStatus host = do
  r <- get ("https://" <> host <> "/status.json")
  pure (r ^. responseBody)
