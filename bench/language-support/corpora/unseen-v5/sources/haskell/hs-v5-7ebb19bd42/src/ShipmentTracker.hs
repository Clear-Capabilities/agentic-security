{-# LANGUAGE OverloadedStrings #-}
module ShipmentTracker (trackerApp) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import qualified Data.Text as T
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status404)
import Web.Spock

data Shipment = Shipment { trackingCode :: Text, shipmentStatus :: Text, carrier :: Text }

instance FromRow Shipment where
  fromRow = Shipment <$> field <*> field <*> field

trackerApp :: Connection -> SpockM () () () ()
trackerApp conn =
  get ("track" <//> var) $ \code -> do
    found <- liftIO (findShipment conn (normalise code))
    case found of
      Nothing -> setStatus status404 >> text "no such shipment"
      Just s  -> text (shipmentStatus s <> " via " <> carrier s)

normalise :: Text -> Text
normalise = T.toUpper . T.strip

findShipment :: Connection -> Text -> IO (Maybe Shipment)
findShipment conn code = do
  rows <- query conn "SELECT tracking_code, status, carrier FROM shipments WHERE tracking_code = ?" (Only code)
  pure (case rows of { (s:_) -> Just s; [] -> Nothing })
