{-# LANGUAGE OverloadedStrings #-}
module Timetable.Feeds.Fetch (fetchRoutes) where

import Web.Scotty
import Network.HTTP.Client
import Network.HTTP.Client.TLS (newTlsManager)
import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.Lazy as TL

fetchRoutes :: ScottyM ()
fetchRoutes = post "/feeds/import" $ do
  school <- param "school" :: ActionM T.Text
  manager <- liftIO newTlsManager
  base <- liftIO (parseRequest "https://calendar.district.example/ical")
  let request = setQueryString [("school", Just (TE.encodeUtf8 school))] base
  response <- liftIO (httpLbs request manager)
  text (TL.pack (show (BL.length (responseBody response))) <> " bytes imported")
