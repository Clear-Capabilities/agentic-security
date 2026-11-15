{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Ferry.BookingLookup (BookingAPI, bookingServer) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (ToJSON)
import Data.Text (Text)
import Database.PostgreSQL.Simple
import GHC.Generics (Generic)
import Servant

data Booking = Booking { reference :: Text, sailing :: Text, vehicles :: Int }
  deriving (Generic)

instance ToJSON Booking

instance FromRow Booking where
  fromRow = Booking <$> field <*> field <*> field

type BookingAPI = "bookings" :> Capture "reference" Text :> Get '[JSON] Booking

bookingServer :: Connection -> Server BookingAPI
bookingServer conn ref = do
  found <- liftIO (query conn "SELECT reference, sailing, vehicles FROM bookings WHERE reference = ?" (Only ref))
  case found of
    [b] -> pure b
    _ -> throwError err404
