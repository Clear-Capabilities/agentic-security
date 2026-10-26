{-# LANGUAGE OverloadedStrings #-}
module Uploads (saveUpload) where

import Network.Wai.Parse (FileInfo(..))
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy as BL
import System.FilePath (takeFileName)
import System.Directory (createDirectoryIfMissing)

saveUpload :: FileInfo BL.ByteString -> IO ()
saveUpload fi = do
  createDirectoryIfMissing True "/srv/uploads"
  let target = "/srv/uploads/" ++ takeFileName (B.unpack (fileName fi))
  BL.writeFile target (fileContent fi)
