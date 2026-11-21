{-# LANGUAGE OverloadedStrings #-}
module Cave.Vents.Commands (commandSocket) where

import qualified Network.WebSockets as WS
import Control.Monad (forever)
import Text.Read (readMaybe)
import qualified Data.Text as T

commandSocket :: (T.Text -> Int -> IO ()) -> WS.ServerApp
commandSocket setVent pending = do
  conn <- WS.acceptRequest pending
  forever $ do
    msg <- WS.receiveData conn :: IO T.Text
    case T.words msg of
      ["set", vent, percentText] | Just percent <- readMaybe (T.unpack percentText) -> do
        setVent vent percent
        WS.sendTextData conn ("ok " <> vent)
      _ -> WS.sendTextData conn ("unrecognised command" :: T.Text)
