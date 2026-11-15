{-# LANGUAGE OverloadedStrings #-}
module Handler.PatientChart (getPatientChartR) where

import Yesod.Auth (requireAuthId)
import Yesod.Core
import Yesod.Persist (get404, runDB)

import Foundation
import Model

assignedTo :: UserId -> Patient -> Handler Patient
assignedTo clinician patient
  | patientClinician patient == clinician = pure patient
  | otherwise = permissionDenied "patient is not on your list"

getPatientChartR :: PatientId -> Handler Value
getPatientChartR pid = do
  clinician <- requireAuthId
  patient <- runDB (get404 pid) >>= assignedTo clinician
  returnJson (object
    [ "mrn" .= patientMrn patient
    , "surname" .= patientSurname patient
    , "ward" .= patientWard patient
    ])
