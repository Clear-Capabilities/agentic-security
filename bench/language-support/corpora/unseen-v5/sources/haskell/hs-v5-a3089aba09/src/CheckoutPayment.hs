{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}
module CheckoutPayment (chargeCard) where

import Control.Monad.Logger (MonadLogger, logInfoN)
import Data.Aeson (FromJSON)
import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics (Generic)

data CardPayment = CardPayment
  { cardNumber  :: Text
  , cardExpiry  :: Text
  , amountCents :: Int
  , orderRef    :: Text
  } deriving (Generic)

instance FromJSON CardPayment

data ChargeResult = Approved Text | Declined Text

chargeCard :: MonadLogger m => CardPayment -> m ChargeResult
chargeCard payment = do
  logInfoN ("charging order " <> orderRef payment <> " card " <> cardNumber payment <> " exp " <> cardExpiry payment)
  if amountCents payment > 0
    then pure (Approved ("ch_" <> T.take 8 (orderRef payment)))
    else pure (Declined "zero amount")
