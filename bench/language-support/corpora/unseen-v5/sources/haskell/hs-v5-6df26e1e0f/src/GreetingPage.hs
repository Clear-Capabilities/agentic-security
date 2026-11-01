{-# LANGUAGE OverloadedStrings #-}
module GreetingPage (greetingRoutes) where

import qualified Data.Text.Lazy as TL
import Web.Scotty

pageShell :: TL.Text -> TL.Text
pageShell inner = TL.concat
  [ "<!doctype html><html><head><title>Northwind</title></head><body>"
  , inner
  , "</body></html>"
  ]

greetingRoutes :: ScottyM ()
greetingRoutes =
  get "/welcome" $ do
    name <- param "name" `rescue` (\_ -> pure "there")
    html (pageShell ("<h1>Welcome back, " <> name <> "</h1><p>Your dashboard is ready.</p>"))
