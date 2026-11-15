{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Labels.Reprint (ReprintApi, reprintServer) where

import Control.Concurrent.Async (mapConcurrently_)
import Control.Monad (when)
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON)
import Data.Text (Text)
import GHC.Generics (Generic)
import Servant

import Printers (printLabel)

data ReprintJob = ReprintJob
  { shipmentRef :: Text
  , printer     :: Text
  , copies      :: Int
  } deriving (Generic)

instance FromJSON ReprintJob

type ReprintApi = "labels" :> "reprint" :> ReqBody '[JSON] ReprintJob :> PostNoContent

maxCopies :: Int
maxCopies = 25

reprintServer :: Server ReprintApi
reprintServer job = do
  when (copies job < 1 || copies job > maxCopies) $
    throwError err422 { errBody = "copies must be between 1 and 25" }
  liftIO (mapConcurrently_ (const (printLabel (printer job) (shipmentRef job))) [1 .. copies job])
  pure NoContent
