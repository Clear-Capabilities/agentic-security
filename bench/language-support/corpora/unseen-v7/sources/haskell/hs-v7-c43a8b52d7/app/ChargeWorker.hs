{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Control.Monad (forM_)
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON, eitherDecodeStrict)
import qualified Data.ByteString.Char8 as BC
import Data.Text (Text)
import GHC.Generics (Generic)
import Katip
import System.IO (stdout)

import Payments (submitCharge)

data Charge = Charge
  { cardNumber :: Text
  , amountCents :: Int
  , invoiceRef :: Text
  } deriving (Generic)

instance FromJSON Charge

main :: IO ()
main = do
  scribe <- mkHandleScribe ColorIfTerminal stdout (permitItem InfoS) V2
  env <- registerScribe "stdout" scribe defaultScribeSettings =<< initLogEnv "charge-worker" "production"
  lines' <- BC.lines <$> BC.getContents
  runKatipContextT env () "charges" $
    forM_ lines' $ \line ->
      case eitherDecodeStrict line of
        Left err -> logFM ErrorS (ls ("unreadable charge: " ++ err))
        Right charge -> process charge

process :: Charge -> KatipContextT IO ()
process charge = do
  logFM InfoS (ls ("charging card " <> cardNumber charge <> " for invoice " <> invoiceRef charge))
  liftIO (submitCharge (cardNumber charge) (amountCents charge))
