{-# LANGUAGE OverloadedStrings #-}
module Warehouse.RobotDispatch (consumeDispatches) where

import Control.Monad (void)
import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Text.Encoding.Error (lenientDecode)
import Network.AMQP
import Shelly

data Dispatch = Dispatch { robot :: Text, bay :: Text }

parseDispatch :: BL.ByteString -> Maybe Dispatch
parseDispatch raw =
  case T.splitOn "|" (TE.decodeUtf8With lenientDecode (BL.toStrict raw)) of
    [r, b] -> Just (Dispatch r b)
    _ -> Nothing

consumeDispatches :: Channel -> IO ()
consumeDispatches chan =
  void $ consumeMsgs chan "robot.dispatch" Ack $ \(msg, env) -> do
    mapM_ moveRobot (parseDispatch (msgBody msg))
    ackEnv env

moveRobot :: Dispatch -> IO ()
moveRobot d = shelly $ silently $
  run_ "sh" ["-c", "robotctl --robot " <> robot d <> " goto " <> bay d]
