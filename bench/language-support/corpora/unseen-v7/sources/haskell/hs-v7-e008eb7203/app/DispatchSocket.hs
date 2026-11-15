{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Control.Monad (forever)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Network.WebSockets as WS

import Dispatch (assignDriver, releaseDriver, listOpen)

main :: IO ()
main = WS.runServer "0.0.0.0" 9200 dispatch

dispatch :: WS.ServerApp
dispatch pending = do
  conn <- WS.acceptRequest pending
  forever $ do
    msg <- WS.receiveData conn :: IO Text
    reply <- handle msg
    WS.sendTextData conn reply

-- messages look like "ASSIGN <shipment> <driver>", "RELEASE <driver>" or "LIST"
handle :: Text -> IO Text
handle msg =
  let parts = T.words msg
      cmd = head parts
  in case cmd of
       "ASSIGN" | [_, shipment, driver] <- parts -> assignDriver shipment driver
       "RELEASE" | [_, driver] <- parts -> releaseDriver driver
       "LIST" -> listOpen
       _ -> pure "ERR unknown command"
