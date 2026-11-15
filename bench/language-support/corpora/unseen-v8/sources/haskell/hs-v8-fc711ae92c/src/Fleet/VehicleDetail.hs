{-# LANGUAGE OverloadedStrings #-}
module Fleet.VehicleDetail (vehicleRoutes) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import Database.PostgreSQL.Simple
import Network.HTTP.Types.Status (status401, status404)
import Web.Scotty
import Web.Scotty.Cookie (getCookie)

operatorId :: (Text -> IO (Maybe Int)) -> ActionM Int
operatorId resolveSession = do
  c <- getCookie "fleet_session"
  r <- maybe (pure Nothing) (liftIO . resolveSession) c
  case r of
    Just oid -> pure oid
    Nothing -> status status401 >> text "operator sign-in required" >> finish

vehicleRoutes :: Connection -> (Text -> IO (Maybe Int)) -> ScottyM ()
vehicleRoutes conn resolveSession =
  get "/vehicles/:vin" $ do
    oid <- operatorId resolveSession
    vin <- param "vin" :: ActionM Text
    rows <- liftIO (query conn "SELECT vin, make, odometer_km FROM vehicles WHERE vin = ? AND operator_id = ?" (vin, oid))
    case rows of
      [(v, mk, km)] -> json (v :: Text, mk :: Text, km :: Int)
      _ -> status status404 >> text "no such vehicle"
