{-# LANGUAGE DataKinds, DeriveGeneric, OverloadedStrings, TypeOperators #-}
module IntegrationTokens (app) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON, ToJSON)
import Data.Text (Text)
import qualified Data.UUID as UUID
import Data.UUID.V4 (nextRandom)
import GHC.Generics (Generic)
import Servant

data NewIntegration = NewIntegration { integrationName :: Text } deriving (Show, Generic)
instance FromJSON NewIntegration

data IssuedToken = IssuedToken { tokenFor :: Text, token :: Text } deriving (Show, Generic)
instance ToJSON IssuedToken

type API = "integrations" :> ReqBody '[JSON] NewIntegration :> Post '[JSON] IssuedToken

freshToken :: IO Text
freshToken = do
  a <- nextRandom
  b <- nextRandom
  pure (UUID.toText a <> UUID.toText b)

issueHandler :: NewIntegration -> Handler IssuedToken
issueHandler req = IssuedToken (integrationName req) <$> liftIO freshToken

app :: Application
app = serve (Proxy :: Proxy API) issueHandler
