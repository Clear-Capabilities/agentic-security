{-# LANGUAGE OverloadedStrings #-}
module Orchestra.MemberPage (memberRoutes) where

import qualified Data.Text.Lazy as TL
import Web.Scotty

data Member = Member { stageName :: TL.Text, section :: TL.Text }

page :: Member -> TL.Text
page m = TL.concat
  [ "<!doctype html><html><body>"
  , "<h1>", stageName m, "</h1>"
  , "<p>Section: ", section m, "</p>"
  , "</body></html>"
  ]

memberRoutes :: ScottyM ()
memberRoutes =
  get "/members/preview" $ do
    name <- param "name"
    sec <- param "section"
    html (page (Member name sec))
