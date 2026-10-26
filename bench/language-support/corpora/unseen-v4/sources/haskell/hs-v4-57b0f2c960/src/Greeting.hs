{-# LANGUAGE OverloadedStrings #-}
module Greeting (greet) where

import Web.Scotty
import Text.Blaze.Html.Renderer.Text (renderHtml)
import qualified Text.Blaze.Html5 as H

greet :: ActionM ()
greet = do
  name <- param "name"
  html (renderHtml (H.h1 ("Welcome back, " <> H.toHtml (name :: String))))
