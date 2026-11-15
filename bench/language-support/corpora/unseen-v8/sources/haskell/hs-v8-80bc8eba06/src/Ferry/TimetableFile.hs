{-# LANGUAGE OverloadedStrings #-}
module Ferry.TimetableFile (timetableApp) where

import qualified Data.ByteString.Lazy as BL
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import Network.HTTP.Types (status200, status404)
import Network.Wai

-- Published timetables, keyed by the route code printed on the booking.
timetables :: Map.Map Text FilePath
timetables = Map.fromList
  [ ("HAR-ORK", "/srv/ferry/timetables/harbour-orkney.pdf")
  , ("HAR-SHE", "/srv/ferry/timetables/harbour-shetland.pdf")
  , ("ORK-SHE", "/srv/ferry/timetables/orkney-shetland.pdf")
  ]

timetableApp :: Application
timetableApp req respond =
  case pathInfo req of
    ["timetables", code] | Just path <- Map.lookup code timetables -> do
      pdf <- BL.readFile path
      respond (responseLBS status200 [("Content-Type", "application/pdf")] pdf)
    _ -> respond (responseLBS status404 [] "unknown route")
