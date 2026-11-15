{-# LANGUAGE OverloadedStrings #-}
module Museum.LoanDocuments (getLoanDocumentR) where

import Museum.Foundation
import Museum.Model
import Yesod.Auth (requireAuthId)
import Yesod.Core
import Yesod.Persist.Core (get404, runDB)

-- Serves the signed loan agreement for a borrowing institution.
getLoanDocumentR :: LoanDocumentId -> Handler TypedContent
getLoanDocumentR docId = do
  _borrower <- requireAuthId
  doc <- runDB (get404 docId)
  addHeader "Content-Disposition" ("attachment; filename=" <> loanDocumentFileName doc)
  sendResponse (TypedContent "application/pdf" (toContent (loanDocumentBytes doc)))
