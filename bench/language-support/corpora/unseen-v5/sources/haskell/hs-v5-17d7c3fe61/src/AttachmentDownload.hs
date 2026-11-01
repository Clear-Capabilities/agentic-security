{-# LANGUAGE OverloadedStrings #-}
module AttachmentDownload (attachmentHandler) where

import qualified Data.ByteString.Char8 as B
import Snap.Core
import Snap.Util.FileServe (serveFileAs)
import System.FilePath ((</>), takeExtension, takeFileName)

contentTypeFor :: FilePath -> Maybe B.ByteString
contentTypeFor p = case takeExtension p of
  ".pdf" -> Just "application/pdf"
  ".png" -> Just "image/png"
  ".jpg" -> Just "image/jpeg"
  _      -> Nothing

attachmentHandler :: Snap ()
attachmentHandler = do
  name <- getParam "name"
  case name of
    Nothing -> modifyResponse (setResponseStatus 400 "name required")
    Just n  -> do
      let leaf = takeFileName (B.unpack n)
          path = "storage/attachments" </> leaf
      case contentTypeFor leaf of
        Nothing -> modifyResponse (setResponseStatus 404 "no such attachment")
        Just ct -> serveFileAs ct path
