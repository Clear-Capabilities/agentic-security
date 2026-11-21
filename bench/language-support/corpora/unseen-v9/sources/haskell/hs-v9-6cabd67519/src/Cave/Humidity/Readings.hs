{-# LANGUAGE OverloadedStrings #-}
module Cave.Humidity.Readings (readingRoutes) where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)

readingRoutes :: (Int -> IO [Double]) -> ScottyM ()
readingRoutes loadSensor = get "/cave/readings" $ do
  sensorText <- param "sensor" :: ActionM String
  let sensorId = read sensorText :: Int
  values <- liftIO (loadSensor sensorId)
  json values
