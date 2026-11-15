{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Ferry.BookingDetail (BookingDetailAPI, Traveller (..), bookingDetailServer) where

import Control.Monad.IO.Class (liftIO)
import Data.Pool (Pool)
import Database.Persist
import Database.Persist.Sql (SqlBackend, runSqlPool)
import Ferry.Model
import Servant

newtype Traveller = Traveller { travellerId :: TravellerId }

type BookingDetailAPI =
  BasicAuth "ferry" Traveller :> "bookings" :> Capture "booking" BookingId :> Get '[JSON] Booking

bookingDetailServer :: Pool SqlBackend -> Server BookingDetailAPI
bookingDetailServer pool traveller bid = do
  found <- liftIO (runSqlPool (selectFirst [BookingId ==. bid, BookingOwner ==. travellerId traveller] []) pool)
  case found of
    Just (Entity _ b) -> pure b
    Nothing -> throwError err404
