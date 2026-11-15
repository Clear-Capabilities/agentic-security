{-# LANGUAGE OverloadedStrings #-}
module Orchestra.PartsLibrary (getPartR) where

import Control.Monad (when)
import Orchestra.Foundation
import Orchestra.Model
import Yesod.Auth (requireAuthId)
import Yesod.Core
import Yesod.Persist.Core (get404, runDB)

-- A player downloads the marked-up part assigned to their chair.
getPartR :: PartId -> Handler TypedContent
getPartR partId = do
  playerId <- requireAuthId
  part <- runDB (get404 partId)
  when (partAssignedTo part /= playerId) notFound
  addHeader "Content-Disposition" ("inline; filename=" <> partFileName part)
  sendResponse (TypedContent "application/pdf" (toContent (partPdf part)))
