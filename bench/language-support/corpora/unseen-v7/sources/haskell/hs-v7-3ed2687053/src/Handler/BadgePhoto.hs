{-# LANGUAGE OverloadedStrings #-}
module Handler.BadgePhoto (postBadgePhotoR) where

import qualified Data.Text as T
import System.FilePath ((</>), (<.>), takeFileName)
import System.Process (callProcess)
import Yesod.Core

import Foundation

postBadgePhotoR :: Handler Value
postBadgePhotoR = do
  (_, uploads) <- runRequestBody
  case lookup "photo" uploads of
    Nothing -> invalidArgs ["photo"]
    Just info -> do
      let name = takeFileName (T.unpack (fileName info))
          dest = "incoming" </> name
      liftIO (fileMove info dest)
      liftIO (makeThumbnail dest (dest <.> "thumb.png"))
      returnJson (object ["stored" .= name])

makeThumbnail :: FilePath -> FilePath -> IO ()
makeThumbnail src out =
  callProcess "convert" [src, "-resize", "128x128", out]
