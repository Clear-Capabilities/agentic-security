{-# LANGUAGE OverloadedStrings #-}
module Cave.Vents.Control (ventSocket) where

import qualified Network.WebSockets as WS
import Control.Monad (forever)
import Text.Read (readMaybe)
import qualified Data.Text as T

ventSocket :: (T.Text -> Int -> IO ()) -> WS.ServerApp
ventSocket setVent pending = do
  conn <- WS.acceptRequest pending
  forever $ do
    msg <- WS.receiveData conn :: IO T.Text
    let parts = T.words msg
        command = head parts
        arguments = drop 1 parts
    case (command, arguments) of
      ("set", [vent, percentText]) | Just percent <- readMaybe (T.unpack percentText) -> do
        setVent vent percent
        WS.sendTextData conn ("ok " <> vent)
      _ -> WS.sendTextData conn ("unrecognised command" :: T.Text)
