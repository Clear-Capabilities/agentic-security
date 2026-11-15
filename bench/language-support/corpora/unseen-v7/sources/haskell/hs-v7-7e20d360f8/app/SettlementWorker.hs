{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Control.Monad (forM_)
import Data.Aeson (FromJSON, eitherDecodeStrict)
import qualified Data.ByteString.Char8 as BC
import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics (Generic)
import System.Log.FastLogger

import Payments (submitCharge)

data Charge = Charge
  { cardNumber :: Text
  , amountCents :: Int
  , invoiceRef :: Text
  } deriving (Generic)

instance FromJSON Charge

main :: IO ()
main = do
  logger <- newStdoutLoggerSet defaultBufSize
  lines' <- BC.lines <$> BC.getContents
  forM_ lines' $ \line ->
    case eitherDecodeStrict line of
      Left err -> pushLogStrLn logger (toLogStr ("unreadable charge: " ++ err))
      Right charge -> process logger charge
  flushLogStr logger

process :: LoggerSet -> Charge -> IO ()
process logger charge = do
  pushLogStrLn logger (toLogStr ("charging card ending " <> T.takeEnd 4 (cardNumber charge) <> " for invoice " <> invoiceRef charge))
  submitCharge (cardNumber charge) (amountCents charge)
