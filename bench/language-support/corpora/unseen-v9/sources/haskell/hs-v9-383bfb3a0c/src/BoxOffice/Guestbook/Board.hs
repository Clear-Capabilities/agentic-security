{-# LANGUAGE OverloadedStrings #-}
module BoxOffice.Guestbook.Board (boardRoutes) where

import Web.Spock
import qualified Data.Text as T

pageAround :: T.Text -> T.Text
pageAround inner = "<html><body><h2>Thanks for signing our wall</h2>" <> inner <> "</body></html>"

escapeHtml :: T.Text -> T.Text
escapeHtml = T.concatMap escapeChar
  where
    escapeChar '<' = "&lt;"
    escapeChar '>' = "&gt;"
    escapeChar '&' = "&amp;"
    escapeChar '"' = "&quot;"
    escapeChar '\'' = "&#39;"
    escapeChar c = T.singleton c

boardRoutes :: SpockM () () () ()
boardRoutes = post "guestbook" $ do
  signature <- param' "signature"
  html (pageAround ("<p class=\"signature\">" <> escapeHtml signature <> "</p>"))
