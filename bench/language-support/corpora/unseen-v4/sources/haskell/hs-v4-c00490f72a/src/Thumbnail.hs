{-# LANGUAGE OverloadedStrings #-}
module Thumbnail (makeThumb) where

import System.Process (callProcess)
import System.FilePath (takeFileName, (</>))
import Web.Scotty
import Data.Text.Lazy (unpack)

makeThumb :: ActionM ()
makeThumb = do
  file <- param "file"
  let src = "uploads" </> takeFileName (unpack file)
  liftAndCatchIO (callProcess "convert" [src, "-resize", "64x64", "thumbs/out.png"])
  text "done"
