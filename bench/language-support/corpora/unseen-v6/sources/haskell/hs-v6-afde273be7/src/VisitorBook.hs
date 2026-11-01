{-# LANGUAGE OverloadedStrings #-}
module VisitorBook (main) where

import qualified Data.Text.Lazy as TL
import Web.Scotty

main :: IO ()
main = scotty 8080 $ do
  get "/visitors/new" $ html form
  post "/visitors" $ do
    message <- param "message"
    html ("<html><body><p>Your entry: " <> escape message <> "</p><a href=/visitors/new>back</a></body></html>")

form :: TL.Text
form = "<html><body><form method=post action=/visitors><textarea name=message></textarea><button>Sign</button></form></body></html>"

escape :: TL.Text -> TL.Text
escape = TL.concatMap replace
  where
    replace '<' = "&lt;"
    replace '>' = "&gt;"
    replace '&' = "&amp;"
    replace '"' = "&quot;"
    replace '\'' = "&#39;"
    replace c = TL.singleton c
