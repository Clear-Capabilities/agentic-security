{-# LANGUAGE OverloadedStrings #-}
module Notebook (deleteNoteR, getNoteR) where

import Data.Aeson (Value, object, (.=))
import Database.Persist (delete, get404)
import Yesod.Auth (requireAuthId)
import Yesod.Core
import Foundation (Handler, Note(..), NoteId)

getNoteR :: NoteId -> Handler Value
getNoteR noteId = do
  _uid <- requireAuthId
  note <- runDB (get404 noteId)
  returnJson (object ["title" .= noteTitle note, "body" .= noteBody note])

deleteNoteR :: NoteId -> Handler Value
deleteNoteR noteId = do
  _uid <- requireAuthId
  _ <- runDB (get404 noteId)
  runDB (delete noteId)
  returnJson (object ["deleted" .= True])
