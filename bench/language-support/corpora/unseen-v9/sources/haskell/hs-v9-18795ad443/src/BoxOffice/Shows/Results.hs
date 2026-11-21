{-# LANGUAGE OverloadedStrings #-}
module BoxOffice.Shows.Results (resultRoutes) where

import Web.Scotty
import Text.Blaze.Html5 ((!))
import qualified Text.Blaze.Html5 as H
import qualified Text.Blaze.Html5.Attributes as A
import Text.Blaze.Html.Renderer.Text (renderHtml)
import qualified Data.Text.Lazy as TL

resultRoutes :: ScottyM ()
resultRoutes = get "/shows/search" $ do
  needle <- param "q" :: ActionM TL.Text
  html $ renderHtml $ H.docTypeHtml $ do
    H.head (H.title "Box office search")
    H.body $ do
      H.h1 "Results"
      H.p ! A.class_ "query" $ do
        "You searched for "
        H.toHtml needle
