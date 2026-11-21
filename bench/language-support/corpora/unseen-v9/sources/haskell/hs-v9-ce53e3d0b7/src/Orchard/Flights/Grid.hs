{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings, DeriveGeneric #-}
module Orchard.Flights.Grid (GridAPI, gridServer) where

import Servant
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON)
import GHC.Generics (Generic)
import qualified Data.ByteString as BS

data GridRequest = GridRequest { orchardId :: Int, gridWidth :: Int, gridHeight :: Int } deriving Generic
instance FromJSON GridRequest

type GridAPI = "flights" :> "plan" :> ReqBody '[JSON] GridRequest :> Post '[JSON] Int

maxCells :: Int
maxCells = 4096 * 4096

gridServer :: (Int -> BS.ByteString -> IO Int) -> Server GridAPI
gridServer saveCoverageMask req
  | gridWidth req < 1 || gridHeight req < 1 = throwError err400 { errBody = "grid dimensions must be positive" }
  | gridWidth req > 4096 || gridHeight req > 4096 || gridWidth req * gridHeight req > maxCells =
      throwError err413 { errBody = "grid exceeds 4096 x 4096 cells" }
  | otherwise = do
      let mask = BS.replicate (gridWidth req * gridHeight req) 0
      liftIO (saveCoverageMask (orchardId req) mask)
