{-# LANGUAGE OverloadedStrings #-}
module CommentFeed (feedHandler) where

import Control.Monad.IO.Class (liftIO)
import Data.IORef
import qualified Data.Text as T
import Happstack.Server
import Lucid

data Comment = Comment { commentAuthor :: T.Text, commentBody :: T.Text }

feedHandler :: IORef [Comment] -> ServerPart Response
feedHandler store = msum
  [ do method POST
       decodeBody (defaultBodyPolicy "/tmp" 0 4096 1024)
       author <- T.pack <$> look "author"
       body   <- T.pack <$> look "body"
       liftIO (modifyIORef store (Comment author body :))
       seeOther ("/feed" :: String) (toResponse ())
  , do method GET
       comments <- liftIO (readIORef store)
       ok (toResponseBS "text/html" (renderBS (renderFeed comments)))
  ]

renderFeed :: [Comment] -> Html ()
renderFeed cs = ul_ (mapM_ renderComment cs)

renderComment :: Comment -> Html ()
renderComment c = li_ (b_ (toHtml (commentAuthor c)) <> ": " <> toHtml (commentBody c))
