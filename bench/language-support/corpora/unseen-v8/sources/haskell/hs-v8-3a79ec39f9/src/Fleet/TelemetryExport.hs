{-# LANGUAGE OverloadedStrings #-}
module Fleet.TelemetryExport (exportRoutes) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy as TL
import qualified Data.Text.Lazy.IO as TLIO
import Web.Scotty

telemetryRoot :: FilePath
telemetryRoot = "/var/lib/fleet/telemetry"

exportRoutes :: ScottyM ()
exportRoutes =
  get "/vehicles/:vehicle/telemetry.csv" $ do
    vehicle <- param "vehicle"
    day <- param "day"
    csv <- liftIO (TLIO.readFile (telemetryRoot ++ "/" ++ TL.unpack vehicle ++ "/" ++ TL.unpack day ++ ".csv"))
    setHeader "Content-Type" "text/csv"
    text csv
