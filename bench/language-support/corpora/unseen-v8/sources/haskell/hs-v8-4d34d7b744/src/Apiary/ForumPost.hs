{-# LANGUAGE OverloadedStrings #-}
module Apiary.ForumPost (postPreview) where

import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Data.Text.Encoding.Error (lenientDecode)
import Lucid
import Snap.Core

postPreview :: Snap ()
postPreview = method POST $ do
  mBody <- getPostParam "body"
  mAuthor <- getPostParam "author"
  let decode = TE.decodeUtf8With lenientDecode
      author = maybe "anonymous keeper" decode mAuthor
      contents = maybe "" decode mBody
  modifyResponse (setContentType "text/html; charset=utf-8")
  writeLBS (renderBS (previewPage author contents))

previewPage :: Text -> Text -> Html ()
previewPage author contents = doctypehtml_ $ do
  head_ (title_ "Preview")
  body_ $ do
    h3_ (toHtml author)
    article_ [class_ "post"] (toHtmlRaw contents)
