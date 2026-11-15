{-# LANGUAGE OverloadedStrings #-}
module Catalogue.CoverImage (coverHandler) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import Snap.Core
import System.FilePath ((</>))

coverDir :: FilePath
coverDir = "/srv/catalogue/covers"

coverHandler :: Snap ()
coverHandler = do
  mName <- getParam "file"
  case mName of
    Nothing -> do
      modifyResponse (setResponseStatus 400 "Bad Request")
      writeBS "file parameter required"
    Just name -> do
      bytes <- liftIO (BS.readFile (coverDir </> B8.unpack name))
      modifyResponse (setContentType "image/jpeg")
      writeBS bytes
