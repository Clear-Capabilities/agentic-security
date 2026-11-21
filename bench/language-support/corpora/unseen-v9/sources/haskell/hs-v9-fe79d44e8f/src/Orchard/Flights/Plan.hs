{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings, DeriveGeneric #-}
module Orchard.Flights.Plan (PlanAPI, planServer) where

import Servant
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON)
import GHC.Generics (Generic)
import qualified Data.ByteString as BS

data PlanRequest = PlanRequest { orchardId :: Int, gridWidth :: Int, gridHeight :: Int } deriving Generic
instance FromJSON PlanRequest

type PlanAPI = "flights" :> "plan" :> ReqBody '[JSON] PlanRequest :> Post '[JSON] Int

planServer :: (Int -> BS.ByteString -> IO Int) -> Server PlanAPI
planServer saveCoverageMask req = do
  let mask = BS.replicate (gridWidth req * gridHeight req) 0
  liftIO (saveCoverageMask (orchardId req) mask)
