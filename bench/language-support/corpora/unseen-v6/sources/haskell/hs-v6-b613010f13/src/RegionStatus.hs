{-# LANGUAGE DataKinds, OverloadedStrings, TypeOperators #-}
module RegionStatus (app) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (Value)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import Network.HTTP.Req
import Servant

type API = "regions" :> Capture "region" Text :> "status" :> Get '[JSON] Value

regionHosts :: Map.Map Text Text
regionHosts = Map.fromList
  [ ("eu-west", "status-eu-west.internal.example.com")
  , ("us-east", "status-us-east.internal.example.com")
  , ("ap-south", "status-ap-south.internal.example.com")
  ]

fetchStatus :: Text -> IO Value
fetchStatus host = runReq defaultHttpConfig $ do
  response <- req GET (https host /: "api" /: "status") NoReqBody jsonResponse mempty
  pure (responseBody response)

statusHandler :: Text -> Handler Value
statusHandler region = case Map.lookup region regionHosts of
  Nothing -> throwError err404 { errBody = "unknown region" }
  Just host -> liftIO (fetchStatus host)

app :: Application
app = serve (Proxy :: Proxy API) statusHandler
