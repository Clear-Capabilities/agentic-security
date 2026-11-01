{-# LANGUAGE OverloadedStrings #-}
module Journal (deleteEntryR, getEntryR) where

import Control.Monad (unless)
import Data.Aeson (Value, object, (.=))
import Database.Persist (delete, get404)
import Yesod.Auth (requireAuthId)
import Yesod.Core
import Foundation (Handler, Entry(..), EntryId)

getEntryR :: EntryId -> Handler Value
getEntryR entryId = do
  uid <- requireAuthId
  entry <- runDB (get404 entryId)
  unless (entryOwner entry == uid) notFound
  returnJson (object ["title" .= entryTitle entry, "body" .= entryBody entry])

deleteEntryR :: EntryId -> Handler Value
deleteEntryR entryId = do
  uid <- requireAuthId
  entry <- runDB (get404 entryId)
  unless (entryOwner entry == uid) notFound
  runDB (delete entryId)
  returnJson (object ["deleted" .= True])
