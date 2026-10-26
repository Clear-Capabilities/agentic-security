{-# LANGUAGE OverloadedStrings #-}
module Thumbnail (makeThumb) where

import System.Process (callCommand)
import Web.Scotty
import Data.Text.Lazy (unpack)

makeThumb :: ActionM ()
makeThumb = do
  file <- param "file"
  let cmd = "convert uploads/" ++ unpack file ++ " -resize 64x64 thumbs/out.png"
  liftAndCatchIO (callCommand cmd)
  text "done"
