{-# LANGUAGE OverloadedStrings #-}
module LiveTail (main) where

import Control.Monad (forever)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Network.WebSockets as WS
import Text.Read (readMaybe)
import qualified Tail

maxLines :: Int
maxLines = 500

main :: IO ()
main = WS.runServer "127.0.0.1" 9170 tailApp

tailApp :: WS.ServerApp
tailApp pending = do
  conn <- WS.acceptRequest pending
  WS.withPingThread conn 30 (pure ()) $ forever $ do
    msg <- WS.receiveData conn :: IO Text
    case readMaybe (T.unpack (T.strip msg)) :: Maybe Int of
      Nothing -> WS.sendTextData conn ("send the number of lines to tail" :: Text)
      Just requested -> do
        let wanted = min maxLines (max 1 requested)
        recent <- Tail.lastLines wanted
        mapM_ (WS.sendTextData conn) recent
