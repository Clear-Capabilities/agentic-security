{-# LANGUAGE OverloadedStrings #-}
module Members.Profile (profileRoutes) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import Lucid
import Web.Scotty

import Members.Store (Member(..), memberByHandle)

profileRoutes :: ScottyM ()
profileRoutes =
  get "/members/:handle" $ do
    handle <- param "handle"
    found <- liftIO (memberByHandle handle)
    case found of
      Nothing -> text "no such member"
      Just m -> html (renderText (profilePage m))

profilePage :: Member -> Html ()
profilePage m = doctypehtml_ $ do
  head_ (title_ (toHtml (memberHandle m)))
  body_ $ do
    h1_ (toHtml (memberHandle m))
    p_ [class_ "joined"] (toHtml ("Member since " <> memberSince m))
    div_ [class_ "bio"] (toHtmlRaw (memberBio m))
