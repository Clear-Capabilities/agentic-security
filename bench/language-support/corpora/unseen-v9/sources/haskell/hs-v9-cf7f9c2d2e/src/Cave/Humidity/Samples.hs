{-# LANGUAGE OverloadedStrings #-}
module Cave.Humidity.Samples (sampleRoutes) where

import Web.Scotty
import Network.HTTP.Types.Status (status400)
import Control.Monad.IO.Class (liftIO)
import Text.Read (readMaybe)

sampleRoutes :: (Int -> IO [Double]) -> ScottyM ()
sampleRoutes loadSensor = get "/cave/readings" $ do
  sensorText <- param "sensor" :: ActionM String
  case readMaybe sensorText :: Maybe Int of
    Nothing -> status status400 >> text "sensor must be a number"
    Just sensorId -> do
      values <- liftIO (loadSensor sensorId)
      json values
