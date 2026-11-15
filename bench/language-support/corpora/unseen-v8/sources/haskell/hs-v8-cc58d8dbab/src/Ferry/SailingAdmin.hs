{-# LANGUAGE OverloadedStrings #-}
module Ferry.SailingAdmin (Session (..), sailingAdminRoutes) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import Network.HTTP.Types (status401)
import Web.Spock

data Session = Anonymous | HarbourMaster Text

requireHarbourMaster :: SpockAction conn Session st Text
requireHarbourMaster = do
  s <- readSession
  case s of
    HarbourMaster who -> pure who
    Anonymous -> do
      setStatus status401
      text "harbour master login required"

sailingAdminRoutes :: (Text -> Int -> IO ()) -> SpockM conn Session st ()
sailingAdminRoutes cancelSailing =
  post ("sailings" <//> var <//> "cancel") $ \sailingId -> do
    who <- requireHarbourMaster
    liftIO (cancelSailing who sailingId)
    text "sailing cancelled"
