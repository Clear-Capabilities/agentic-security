{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Grants.ApplicationFetch (Applicant (..), ApplicationAPI, applicationServer) where

import Control.Monad.IO.Class (liftIO)
import Data.Pool (Pool)
import Database.Persist
import Database.Persist.Sql (SqlBackend, runSqlPool)
import Grants.Model
import Servant

newtype Applicant = Applicant { applicantId :: ApplicantId }

type ApplicationAPI =
  BasicAuth "grants" Applicant :> "applications" :> Capture "id" ApplicationId :> Get '[JSON] Application

applicationServer :: Pool SqlBackend -> Server ApplicationAPI
applicationServer pool _applicant appId = do
  found <- liftIO (runSqlPool (get appId) pool)
  maybe (throwError err404) pure found
