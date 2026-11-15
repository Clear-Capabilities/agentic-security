{-# LANGUAGE OverloadedStrings #-}
module Grants.ApplicantList (getApplicantsR) where

import Data.Text (Text)
import Database.Persist
import Grants.Foundation
import Grants.Model
import Yesod.Core
import Yesod.Persist.Core (runDB)

-- Lists every application filed under one funding call.
getApplicantsR :: Text -> Handler Value
getApplicantsR callCode = do
  mInstitution <- lookupGetParam "institution"
  let filters = [ApplicationCallCode ==. callCode]
             ++ maybe [] (\i -> [ApplicationInstitution ==. i]) mInstitution
  apps <- runDB (selectList filters [Asc ApplicationSubmittedAt, LimitTo 200])
  returnJson (map (applicationTitle . entityVal) apps)
