{-# LANGUAGE OverloadedStrings #-}
module Timetable.Feeds.Import (importRoutes) where

import Web.Scotty
import Network.HTTP.Client
import Network.HTTP.Client.TLS (newTlsManager)
import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text.Lazy as TL

importRoutes :: ScottyM ()
importRoutes = post "/feeds/import" $ do
  feedUrl <- param "url" :: ActionM TL.Text
  manager <- liftIO newTlsManager
  request <- liftIO (parseRequest (TL.unpack feedUrl))
  response <- liftIO (httpLbs request manager)
  text (TL.pack (show (BL.length (responseBody response))) <> " bytes imported")
