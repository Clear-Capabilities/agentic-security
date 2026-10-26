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
  newBio <- requireJsonBody :: Handler T.Text
  runDB (update (toSqlKey pid) [ProfileBio =. newBio])
  returnJson ("updated" :: T.Text)
