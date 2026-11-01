{-# LANGUAGE OverloadedStrings #-}
module CommentThread (main) where

import Control.Monad (msum)
import Data.Text (Text)
import Happstack.Server
import Text.Blaze.Html5 (Html, (!))
import qualified Text.Blaze.Html5 as H
import qualified Text.Blaze.Html5.Attributes as A

main :: IO ()
main = simpleHTTP nullConf $ msum
  [ dir "comments" $ dir "preview" $ do
      method GET
      body <- lookText' "body"
      author <- lookText' "author"
      ok (toResponse (renderComment author body))
  , notFound (toResponse ("no such page" :: String))
  ]

renderComment :: Text -> Text -> Html
renderComment author body = H.docTypeHtml $ do
  H.head (H.title "Comment preview")
  H.body $ H.article ! A.class_ "comment" $ do
    H.h2 (H.toHtml author)
    H.p (H.preEscapedToHtml body)
