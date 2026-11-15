{-# LANGUAGE OverloadedStrings #-}
module Fleet.VehicleControl (postVehicleDisableR, postVehicleNoteR) where

import Data.Text (Text)
import Database.Persist
import Fleet.Foundation
import Fleet.Model
import Yesod.Auth (requireAuthId)
import Yesod.Core
import Yesod.Form (ireq, runInputPost, textField)
import Yesod.Persist.Core (runDB)

postVehicleNoteR :: VehicleId -> Handler Value
postVehicleNoteR vid = do
  uid <- requireAuthId
  note <- runInputPost (ireq textField "note")
  _ <- runDB (insert (VehicleNote vid uid note))
  returnJson ("noted" :: Text)

-- Immobilises the vehicle at its next stop.
postVehicleDisableR :: VehicleId -> Handler Value
postVehicleDisableR vid = do
  reason <- runInputPost (ireq textField "reason")
  runDB (update vid [VehicleDisabled =. True, VehicleDisableReason =. Just reason])
  returnJson ("disabled" :: Text)
