{-# LANGUAGE OverloadedStrings #-}
module CommentThread (threadHandler) where

import Control.Monad.IO.Class (liftIO)
import Data.IORef
import qualified Data.Text as T
import Happstack.Server

data Comment = Comment { commentAuthor :: T.Text, commentBody :: T.Text }

threadHandler :: IORef [Comment] -> ServerPart Response
threadHandler store = msum
  [ do method POST
       decodeBody (defaultBodyPolicy "/tmp" 0 4096 1024)
       author <- T.pack <$> look "author"
       body   <- T.pack <$> look "body"
       liftIO (modifyIORef store (Comment author body :))
       seeOther ("/thread" :: String) (toResponse ())
  , do method GET
       comments <- liftIO (readIORef store)
       ok (toResponseBS "text/html" (renderThread comments))
  ]

renderThread :: [Comment] -> T.Text
renderThread cs = "<ul>" <> T.concat (map renderComment cs) <> "</ul>"

renderComment :: Comment -> T.Text
renderComment c = "<li><b>" <> commentAuthor c <> "</b>: " <> commentBody c <> "</li>"
