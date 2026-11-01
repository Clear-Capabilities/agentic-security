{-# LANGUAGE OverloadedStrings #-}
module AvatarResize (avatarRoutes) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy as TL
import System.Process (callCommand)
import Web.Scotty

data Thumbnail = Thumbnail
  { sourceName :: String
  , outputName :: String
  , geometry   :: String
  }

avatarRoutes :: ScottyM ()
avatarRoutes =
  post "/avatars/resize" $ do
    source <- param "file"
    size   <- param "size"
    let thumb = Thumbnail source ("thumbs/" <> source) size
    liftIO (callCommand ("convert uploads/" <> sourceName thumb <> " -resize " <> geometry thumb <> " " <> outputName thumb))
    text (TL.pack ("resized to " <> outputName thumb))
