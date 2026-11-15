{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Control.Monad (forever)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Network.WebSockets as WS

import Dispatch (assignDriver, releaseDriver, listOpen)

main :: IO ()
main = WS.runServer "0.0.0.0" 9201 dispatch

dispatch :: WS.ServerApp
dispatch pending = do
  conn <- WS.acceptRequest pending
  forever $ do
    msg <- WS.receiveData conn :: IO Text
    reply <- handle msg
    WS.sendTextData conn reply

handle :: Text -> IO Text
handle msg =
  case T.words msg of
    ["ASSIGN", shipment, driver] -> assignDriver shipment driver
    ["RELEASE", driver] -> releaseDriver driver
    ["LIST"] -> listOpen
    [] -> pure "ERR empty message"
    _ -> pure "ERR unknown command"
