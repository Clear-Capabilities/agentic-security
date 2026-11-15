{-# LANGUAGE OverloadedStrings #-}
module Lab.SampleResults (resultRoutes) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401)
import Web.Scotty
import Web.Scotty.Cookie (getCookie)

currentAnalyst :: (Text -> IO (Maybe Int)) -> ActionM Int
currentAnalyst resolve = do
  c <- getCookie "lab_session"
  r <- maybe (pure Nothing) (liftIO . resolve) c
  case r of
    Just a -> pure a
    Nothing -> status status401 >> text "sign in first" >> finish

resultRoutes :: Connection -> (Text -> IO (Maybe Int)) -> ScottyM ()
resultRoutes conn resolve =
  get "/samples/:sample/results" $ do
    _analyst <- currentAnalyst resolve
    sampleId <- param "sample" :: ActionM Int
    rows <- liftIO (query conn "SELECT analyte, value, unit FROM results WHERE sample_id = ?" (Only sampleId))
    json (rows :: [(Text, Double, Text)])
