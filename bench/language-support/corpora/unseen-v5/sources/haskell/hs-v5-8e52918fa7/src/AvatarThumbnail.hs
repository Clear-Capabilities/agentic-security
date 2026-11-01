{-# LANGUAGE OverloadedStrings #-}
module AvatarThumbnail (avatarRoutes) where

import Control.Monad (unless)
import Control.Monad.IO.Class (liftIO)
import Data.Char (isAlphaNum)
import qualified Data.Text.Lazy as TL
import System.Process (readProcess)
import Web.Scotty

data Thumbnail = Thumbnail
  { sourceName :: String
  , outputName :: String
  }

plainName :: String -> Bool
plainName s = not (null s) && length s <= 64 && all (\c -> isAlphaNum c || c == '-') s

avatarRoutes :: ScottyM ()
avatarRoutes =
  post "/avatars/thumbnail" $ do
    source <- param "file"
    unless (plainName source) $ raise "file must be a plain identifier"
    let thumb = Thumbnail source ("thumbs/" <> source)
    _ <- liftIO (readProcess "convert" ["uploads/" <> sourceName thumb, "-resize", "128x128", outputName thumb] "")
    text (TL.pack ("resized to " <> outputName thumb))
