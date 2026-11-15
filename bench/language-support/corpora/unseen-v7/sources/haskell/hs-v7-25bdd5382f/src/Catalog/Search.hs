{-# LANGUAGE OverloadedStrings #-}
module Catalog.Search (searchRoutes) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import qualified Data.Text as T
import Web.Spock

import Catalog.Store (Store, findParts)

searchRoutes :: Store -> SpockM () () () ()
searchRoutes store =
  get "parts" $ do
    q <- param' "q"
    parts <- liftIO (findParts store q)
    html (renderResults q parts)

renderResults :: Text -> [(Text, Text)] -> Text
renderResults q parts = T.concat
  [ "<!doctype html><html><body>"
  , "<h1>Results for ", q, "</h1>"
  , "<ul>", T.concat [ "<li>" <> sku <> ": " <> name <> "</li>" | (sku, name) <- parts ], "</ul>"
  , "<p>", T.pack (show (length parts)), " part(s) matched.</p>"
  , "</body></html>"
  ]
