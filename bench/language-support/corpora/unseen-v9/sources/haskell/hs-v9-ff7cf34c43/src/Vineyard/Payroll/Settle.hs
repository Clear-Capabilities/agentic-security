{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}
module Vineyard.Payroll.Settle (startSettleWorker) where

import Network.AMQP
import Data.Aeson (FromJSON, eitherDecode)
import GHC.Generics (Generic)
import System.Log.Logger (infoM, warningM)
import qualified Data.Text as T

data Payout = Payout { pickerId :: Int, cardNumber :: T.Text, amountCents :: Int } deriving Generic
instance FromJSON Payout

startSettleWorker :: Channel -> (Payout -> IO ()) -> IO ()
startSettleWorker chan settle = do
  _ <- consumeMsgs chan "payroll.payouts" Ack (handlePayout settle)
  pure ()

handlePayout :: (Payout -> IO ()) -> (Message, Envelope) -> IO ()
handlePayout settle (msg, env) =
  case eitherDecode (msgBody msg) of
    Left err -> warningM "payroll.payout" ("rejected payout message: " ++ err) >> rejectEnv env False
    Right payout -> do
      infoM "payroll.payout" ("settling picker " ++ show (pickerId payout) ++ " card ending " ++ T.unpack (T.takeEnd 4 (cardNumber payout)) ++ " cents " ++ show (amountCents payout))
      settle payout
      ackEnv env
