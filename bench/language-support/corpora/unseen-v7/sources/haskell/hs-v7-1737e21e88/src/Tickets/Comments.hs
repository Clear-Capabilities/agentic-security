{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Tickets.Comments (CommentsApi, commentsServer) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import Servant
import Servant.HTML.Blaze (HTML)
import Text.Blaze.Html (Html, preEscapedToHtml, toHtml)
import qualified Text.Blaze.Html5 as H
import qualified Text.Blaze.Html5.Attributes as A

import Tickets.Store (Comment(..), loadComments)

type CommentsApi =
  "tickets" :> Capture "id" Int :> "comments" :> Get '[HTML] Html

commentsServer :: Server CommentsApi
commentsServer tid = do
  comments <- liftIO (loadComments tid)
  pure (page tid comments)

page :: Int -> [Comment] -> Html
page tid comments = H.docTypeHtml $ do
  H.head (H.title (toHtml ("Ticket #" ++ show tid)))
  H.body $ do
    H.h1 (toHtml ("Comments on ticket " ++ show tid))
    mapM_ renderComment comments

renderComment :: Comment -> Html
renderComment c = H.div H.! A.class_ "comment" $ do
  H.span H.! A.class_ "author" $ toHtml (commentAuthor c)
  H.p (preEscapedToHtml (commentBody c))
