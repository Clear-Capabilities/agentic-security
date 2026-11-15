{-# LANGUAGE OverloadedStrings #-}
module Ferry.PaymentTrace (CardPayment (..), tracePayment) where

import Data.Text (Text)
import qualified Data.Text as T
import System.Log.FastLogger (LoggerSet, ToLogStr (..), pushLogStrLn)

data CardPayment = CardPayment { bookingRef :: Text, cardNumber :: Text, expiry :: Text, amountPence :: Int }

tracePayment :: LoggerSet -> CardPayment -> IO ()
tracePayment logger p =
  pushLogStrLn logger (toLogStr line)
  where
    line = T.intercalate " "
      [ "payment", bookingRef p
      , "card=" <> cardNumber p
      , "exp=" <> expiry p
      , "amount=" <> T.pack (show (amountPence p))
      ]
