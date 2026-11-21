{-# LANGUAGE OverloadedStrings #-}
module Timetable.Substitutes.Live (substituteSocket) where

import qualified Network.WebSockets as WS
import Network.HTTP.Conduit (simpleHttp)
import Control.Monad (forever)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text as T

substituteSocket :: WS.ServerApp
substituteSocket pending = do
  conn <- WS.acceptRequest pending
  forever $ do
    msg <- WS.receiveData conn :: IO T.Text
    case T.stripPrefix "calendar " msg of
      Just calendarUrl -> do
        body <- simpleHttp (T.unpack calendarUrl)
        WS.sendTextData conn (T.pack (show (BL.length body)) <> " bytes of calendar")
      Nothing -> WS.sendTextData conn ("unknown command" :: T.Text)
