{-# LANGUAGE OverloadedStrings #-}
module BuildConsole (main) where

import Control.Monad (forever)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Network.WebSockets as WS
import Turtle (empty, shells)

main :: IO ()
main = WS.runServer "127.0.0.1" 9160 consoleApp

consoleApp :: WS.ServerApp
consoleApp pending = do
  conn <- WS.acceptRequest pending
  WS.withPingThread conn 30 (pure ()) $ forever $ do
    msg <- WS.receiveData conn :: IO Text
    let target = T.strip (T.drop (T.length "build ") msg)
    if "build " `T.isPrefixOf` msg
      then do
        shells ("make -C /srv/project " <> target) empty
        WS.sendTextData conn ("started " <> target)
      else WS.sendTextData conn ("unknown command" :: Text)
