{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Museum.LoanNotes (NotesAPI, notesServer) where

import Data.Text (Text)
import Servant
import Servant.HTML.Blaze (HTML)
import Text.Blaze.Html5 (Html, (!))
import qualified Text.Blaze.Html5 as H
import qualified Text.Blaze.Html5.Attributes as A
import Web.FormUrlEncoded (FromForm (..), parseUnique)

newtype NoteForm = NoteForm { noteBody :: Text }

instance FromForm NoteForm where
  fromForm f = NoteForm <$> parseUnique "note" f

type NotesAPI = "loans" :> Capture "loan" Int :> "notes" :> ReqBody '[FormUrlEncoded] NoteForm :> Post '[HTML] Html

notesServer :: Server NotesAPI
notesServer loan form = pure (notePage loan (noteBody form))

notePage :: Int -> Text -> Html
notePage loan note = H.docTypeHtml $ do
  H.head (H.title "Loan note recorded")
  H.body $ do
    H.h2 (H.toHtml ("Loan #" ++ show loan))
    H.div ! A.class_ "note" $ H.preEscapedToHtml note
