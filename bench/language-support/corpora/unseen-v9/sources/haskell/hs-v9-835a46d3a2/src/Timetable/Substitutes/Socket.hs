{-# LANGUAGE OverloadedStrings #-}
module Timetable.Substitutes.Socket (substituteSocket) where

import qualified Network.WebSockets as WS
import Network.HTTP.Conduit (simpleHttp)
import Network.HTTP.Types.URI (urlEncode)
import Control.Monad (forever)
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE

substituteSocket :: WS.ServerApp
substituteSocket pending = do
  conn <- WS.acceptRequest pending
  forever $ do
    msg <- WS.receiveData conn :: IO T.Text
    case T.stripPrefix "calendar " msg of
      Just teacherId -> do
        let encoded = BC.unpack (urlEncode True (TE.encodeUtf8 teacherId))
        body <- simpleHttp ("https://staff.district.example/calendar.ics?teacher=" ++ encoded)
        WS.sendTextData conn (T.pack (show (BL.length body)) <> " bytes of calendar")
      Nothing -> WS.sendTextData conn ("unknown command" :: T.Text)
