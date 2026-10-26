{-# LANGUAGE QuasiQuotes, TemplateHaskell, TypeFamilies, OverloadedStrings #-}
module Comments (getCommentR) where

import Yesod
import Text.Blaze.Html (preEscapedToHtml)
import qualified Data.Text as T

data Site = Site
mkYesod "Site" [parseRoutes| /comment/#T.Text CommentR GET |]
instance Yesod Site

getCommentR :: T.Text -> Handler Html
getCommentR body = defaultLayout $ do
  setTitle "Comment"
  [whamlet|<div .comment>#{preEscapedToHtml body}|]
