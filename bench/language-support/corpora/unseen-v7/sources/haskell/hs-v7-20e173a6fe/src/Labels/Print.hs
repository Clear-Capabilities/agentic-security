{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Labels.Print (PrintApi, printServer) where

import Control.Concurrent.Async (mapConcurrently_)
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON)
import Data.Text (Text)
import GHC.Generics (Generic)
import Servant

import Printers (printLabel)

data PrintJob = PrintJob
  { shipmentRef :: Text
  , printer     :: Text
  , copies      :: Int
  } deriving (Generic)

instance FromJSON PrintJob

type PrintApi = "labels" :> "print" :> ReqBody '[JSON] PrintJob :> PostNoContent

printServer :: Server PrintApi
printServer job = do
  liftIO (mapConcurrently_ (const (printLabel (printer job) (shipmentRef job))) [1 .. copies job])
  pure NoContent
