{-# LANGUAGE OverloadedStrings #-}
module Warehouse.RobotCommand (consumeCommands, handleDispatch) where

import Control.Monad (void)
import qualified Data.ByteString.Lazy as BL
import Data.Char (isAlphaNum)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Text.Encoding.Error (lenientDecode)
import Network.AMQP
import System.Process.Typed (proc, runProcess_)

data Dispatch = Dispatch { robotName :: Text, bayCode :: Text }

validBay :: Text -> Bool
validBay b = not (T.null b) && T.length b <= 8 && T.all (\c -> isAlphaNum c || c == '-') b

knownRobots :: [Text]
knownRobots = ["atlas", "bishop", "cass", "dory"]

handleDispatch :: Dispatch -> IO (Either String ())
handleDispatch d
  | robotName d `notElem` knownRobots = pure (Left "unknown robot")
  | not (validBay (bayCode d)) = pure (Left "bad bay code")
  | otherwise = Right <$> runProcess_ (proc "robotctl" ["--robot", T.unpack (robotName d), "goto", T.unpack (bayCode d)])

consumeCommands :: Channel -> (String -> IO ()) -> IO ()
consumeCommands chan report =
  void $ consumeMsgs chan "robot.commands" Ack $ \(msg, env) -> do
    case T.splitOn "|" (TE.decodeUtf8With lenientDecode (BL.toStrict (msgBody msg))) of
      [r, b] -> handleDispatch (Dispatch r b) >>= either report (const (pure ()))
      _ -> report "malformed dispatch"
    ackEnv env
