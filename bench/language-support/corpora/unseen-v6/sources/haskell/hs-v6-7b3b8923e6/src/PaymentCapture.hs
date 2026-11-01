{-# LANGUAGE DataKinds, DeriveGeneric, OverloadedStrings, TypeOperators #-}
module PaymentCapture (app) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON)
import Data.Text (Text)
import GHC.Generics (Generic)
import Katip
import Servant

data CardPayment = CardPayment
  { cardNumber :: Text
  , expiry :: Text
  , amountCents :: Int
  , merchantRef :: Text
  } deriving (Show, Generic)
instance FromJSON CardPayment

type API = "payments" :> "card" :> ReqBody '[JSON] CardPayment :> Post '[JSON] Text

recordAttempt :: LogEnv -> CardPayment -> IO ()
recordAttempt env payment = runKatipContextT env () "payments" $
  logFM InfoS (ls ("capturing " <> merchantRef payment <> " card=" <> cardNumber payment <> " exp=" <> expiry payment))

captureHandler :: LogEnv -> CardPayment -> Handler Text
captureHandler env payment = do
  liftIO (recordAttempt env payment)
  pure ("captured " <> merchantRef payment)

app :: LogEnv -> Application
app env = serve (Proxy :: Proxy API) (captureHandler env)
