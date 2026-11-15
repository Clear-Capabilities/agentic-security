{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
module Warehouse.RobotSocket (RobotStatus (..), robotApp) where

import Control.Monad (forever)
import Data.Aeson (FromJSON, decode)
import Data.Maybe (fromJust)
import Data.Text (Text)
import GHC.Generics (Generic)
import qualified Network.WebSockets as WS

data RobotStatus = RobotStatus { robotId :: Text, battery :: Int, aisle :: Text }
  deriving (Generic, Show)

instance FromJSON RobotStatus

robotApp :: (RobotStatus -> IO ()) -> WS.ServerApp
robotApp record pending = do
  conn <- WS.acceptRequest pending
  WS.withPingThread conn 30 (pure ()) $ forever $ do
    msg <- WS.receiveData conn
    let status = fromJust (decode msg)
    record status
