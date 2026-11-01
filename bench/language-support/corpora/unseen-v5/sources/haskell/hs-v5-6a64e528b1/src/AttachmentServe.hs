{-# LANGUAGE OverloadedStrings #-}
module AttachmentServe (attachmentHandler) where

import qualified Data.ByteString.Char8 as B
import Snap.Core
import Snap.Util.FileServe (serveFileAs)
import System.FilePath ((</>), takeExtension)

contentTypeFor :: FilePath -> B.ByteString
contentTypeFor p = case takeExtension p of
  ".pdf" -> "application/pdf"
  ".png" -> "image/png"
  ".jpg" -> "image/jpeg"
  _      -> "application/octet-stream"

attachmentHandler :: Snap ()
attachmentHandler = do
  name <- getParam "name"
  case name of
    Nothing -> modifyResponse (setResponseStatus 400 "name required")
    Just n  -> do
      let path = "storage/attachments" </> B.unpack n
      serveFileAs (contentTypeFor path) path
