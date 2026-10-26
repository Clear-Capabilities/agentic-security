{-# LANGUAGE QuasiQuotes, TemplateHaskell, TypeFamilies, OverloadedStrings #-}
module Profiles (putProfileR) where

import Yesod
import Database.Persist.Sql
import qualified Data.Text as T

data App = App
mkYesod "App" [parseRoutes| /profile/#Int64 ProfileR PUT |]
instance Yesod App

putProfileR :: Int64 -> Handler Value
putProfileR pid = do
  uid <- requireAuthId
  mProfile <- runDB (get (toSqlKey pid))
  case mProfile of
    Just p | profileUser p == uid -> do
      newBio <- requireJsonBody :: Handler T.Text
      runDB (update (toSqlKey pid) [ProfileBio =. newBio])
      returnJson ("updated" :: T.Text)
    _ -> permissionDenied "not your profile"
