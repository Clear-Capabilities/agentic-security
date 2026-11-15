{-# LANGUAGE OverloadedStrings #-}
module Catalog.Lookup (lookupHandler) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Snap.Core
import Text.Blaze.Html.Renderer.Utf8 (renderHtml)
import Text.Blaze.Html5 (Html, toHtml, (!))
import qualified Text.Blaze.Html5 as H
import qualified Text.Blaze.Html5.Attributes as A

import Catalog.Store (Store, findParts)

lookupHandler :: Store -> Snap ()
lookupHandler store = do
  q <- maybe "" TE.decodeUtf8 <$> getParam "q"
  parts <- liftIO (findParts store q)
  modifyResponse (setContentType "text/html; charset=utf-8")
  writeLBS (renderHtml (resultsPage q parts))

resultsPage :: T.Text -> [(T.Text, T.Text)] -> Html
resultsPage q parts = H.docTypeHtml $ do
  H.head (H.title "Parts")
  H.body $ do
    H.h1 (toHtml ("Results for " <> q))
    H.ul ! A.class_ "parts" $
      mapM_ (\(sku, name) -> H.li (toHtml (sku <> ": " <> name))) parts
