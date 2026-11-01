{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}
module CheckoutEvents (chargeCard) where

import Data.Aeson (FromJSON)
import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics (Generic)
import Katip

data CardPayment = CardPayment
  { cardNumber  :: Text
  , cardExpiry  :: Text
  , amountCents :: Int
  , orderRef    :: Text
  } deriving (Generic)

instance FromJSON CardPayment

data ChargeResult = Approved Text | Declined Text

lastFour :: Text -> Text
lastFour = T.takeEnd 4

chargeCard :: KatipContext m => CardPayment -> m ChargeResult
chargeCard payment = do
  logFM InfoS (ls ("charging order " <> orderRef payment <> " card ending " <> lastFour (cardNumber payment)))
  if amountCents payment > 0
    then pure (Approved ("ch_" <> T.take 8 (orderRef payment)))
    else pure (Declined "zero amount")
