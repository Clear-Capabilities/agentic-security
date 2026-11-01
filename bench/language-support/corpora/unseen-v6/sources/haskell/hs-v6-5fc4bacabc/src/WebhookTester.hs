{-# LANGUAGE DataKinds, DeriveGeneric, OverloadedStrings, TypeOperators #-}
module WebhookTester (app) where

import Control.Lens ((^.))
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON, ToJSON, object, (.=))
import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics (Generic)
import Network.Wreq (post, responseStatus, statusCode)
import Servant

data TestRequest = TestRequest { endpoint :: Text, sampleEvent :: Text }
  deriving (Show, Generic)
instance FromJSON TestRequest

data TestResult = TestResult { deliveredTo :: Text, statusReturned :: Int }
  deriving (Show, Generic)
instance ToJSON TestResult

type API = "webhooks" :> "test" :> ReqBody '[JSON] TestRequest :> Post '[JSON] TestResult

deliverSample :: TestRequest -> IO TestResult
deliverSample req = do
  response <- post (T.unpack (endpoint req)) (object ["event" .= sampleEvent req, "sample" .= True])
  pure (TestResult (endpoint req) (response ^. responseStatus . statusCode))

testHandler :: TestRequest -> Handler TestResult
testHandler = liftIO . deliverSample

app :: Application
app = serve (Proxy :: Proxy API) testHandler
