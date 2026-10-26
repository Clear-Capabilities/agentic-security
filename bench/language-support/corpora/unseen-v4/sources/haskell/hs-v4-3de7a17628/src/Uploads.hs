{-# LANGUAGE OverloadedStrings #-}
module Uploads (saveUpload) where

import Network.Wai.Parse (FileInfo(..))
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy as BL

saveUpload :: FileInfo BL.ByteString -> IO ()
saveUpload fi = do
  let target = "/srv/uploads/" ++ B.unpack (fileName fi)
  BL.writeFile target (fileContent fi)
