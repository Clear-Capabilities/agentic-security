{-# LANGUAGE OverloadedStrings #-}
module WelcomePage (welcomeRoutes) where

import qualified Data.Text.Lazy as TL
import Text.Blaze.Html.Renderer.Text (renderHtml)
import Text.Blaze.Html5 (Html, toHtml)
import qualified Text.Blaze.Html5 as H
import Web.Scotty

pageShell :: Html -> Html
pageShell inner = H.docTypeHtml $ do
  H.head (H.title "Northwind")
  H.body inner

welcomeRoutes :: ScottyM ()
welcomeRoutes =
  get "/welcome" $ do
    name <- param "name" `rescue` (\_ -> pure ("there" :: TL.Text))
    html (renderHtml (pageShell (greeting name)))

greeting :: TL.Text -> Html
greeting name = do
  H.h1 ("Welcome back, " <> toHtml name)
  H.p "Your dashboard is ready."
