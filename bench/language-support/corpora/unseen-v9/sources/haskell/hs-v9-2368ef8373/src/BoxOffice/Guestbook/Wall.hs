{-# LANGUAGE OverloadedStrings #-}
module BoxOffice.Guestbook.Wall (guestbookRoutes) where

import Web.Spock
import qualified Data.Text as T

pageAround :: T.Text -> T.Text
pageAround inner = "<html><body><h2>Thanks for signing our wall</h2>" <> inner <> "</body></html>"

guestbookRoutes :: SpockM () () () ()
guestbookRoutes = post "guestbook" $ do
  signature <- param' "signature"
  html (pageAround ("<p class=\"signature\">" <> signature <> "</p>"))
