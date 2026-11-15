{-# LANGUAGE OverloadedStrings #-}
module Handler.PatientSearch (getPatientSearchR) where

import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import Database.Persist.Sql (Entity(..), rawSql)
import Yesod.Core
import Yesod.Persist (YesodDB, runDB)

import Foundation
import Model

getPatientSearchR :: Handler Value
getPatientSearchR = do
  surname <- fromMaybe "" <$> lookupGetParam "surname"
  found <- runDB (searchBySurname surname)
  returnJson (map (patientMrn . entityVal) found)

searchBySurname :: Text -> YesodDB App [Entity Patient]
searchBySurname surname =
  rawSql ("SELECT ?? FROM patient WHERE surname LIKE '" <> T.strip surname <> "%' ORDER BY surname") []
