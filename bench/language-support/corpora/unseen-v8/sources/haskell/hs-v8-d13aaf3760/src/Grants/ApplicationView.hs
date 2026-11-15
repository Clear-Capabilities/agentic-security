{-# LANGUAGE OverloadedStrings #-}
module Grants.ApplicationView (previewHandler) where

import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Lazy as TL
import qualified Data.Text.Lazy.Encoding as TLE
import Happstack.Server

escapeHtml :: Text -> Text
escapeHtml = T.concatMap esc
  where
    esc '<' = "&lt;"
    esc '>' = "&gt;"
    esc '&' = "&amp;"
    esc '"' = "&quot;"
    esc '\'' = "&#39;"
    esc c = T.singleton c

data Preview = Preview { previewTitle :: Text, abstract :: Text }

renderPreview :: Preview -> Text
renderPreview p = T.concat
  [ "<!doctype html><html><body><article class=\"application\">"
  , "<h1>", escapeHtml (previewTitle p), "</h1>"
  , "<p class=\"abstract\">", escapeHtml (abstract p), "</p>"
  , "</article></body></html>"
  ]

previewHandler :: ServerPart Response
previewHandler = dir "applications" $ dir "preview" $ do
  method POST
  decodeBody (defaultBodyPolicy "/tmp" 0 65536 4096)
  title <- lookText' "title"
  summary <- lookText' "abstract"
  ok (toResponseBS "text/html; charset=utf-8" (TLE.encodeUtf8 (TL.fromStrict (renderPreview (Preview title summary)))))
