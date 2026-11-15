{-# LANGUAGE OverloadedStrings #-}
module Handler.PatientRecord (getPatientRecordR) where

import Yesod.Auth (requireAuthId)
import Yesod.Core
import Yesod.Persist (get404, runDB)

import Foundation
import Model

getPatientRecordR :: PatientId -> Handler Value
getPatientRecordR pid = do
  _clinician <- requireAuthId
  patient <- runDB (get404 pid)
  returnJson (object
    [ "mrn" .= patientMrn patient
    , "surname" .= patientSurname patient
    , "ward" .= patientWard patient
    ])
