{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings #-}
module ImportBundle (BundleApi, bundleServer) where

import Codec.Compression.GZip (decompress)
import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Lazy.Char8 as BLC
import Data.Int (Int64)
import Servant

type BundleApi = "imports" :> "bundle" :> ReqBody '[OctetStream] BL.ByteString :> Post '[JSON] Int

maxExpandedBytes :: Int64
maxExpandedBytes = 32 * 1024 * 1024

gzipMagic :: BL.ByteString -> Maybe BL.ByteString
gzipMagic body
  | BL.take 2 body == BL.pack [0x1f, 0x8b] = Just body
  | otherwise = Nothing

bundleServer :: Server BundleApi
bundleServer body =
  case gzipMagic body of
    Nothing -> throwError err415 { errBody = "gzip archive expected" }
    Just archive -> do
      let expanded = BL.take (maxExpandedBytes + 1) (decompress archive)
      if BL.length expanded > maxExpandedBytes
        then throwError err413 { errBody = "archive expands past the allowed size" }
        else liftIO (storeRows expanded)

storeRows :: BL.ByteString -> IO Int
storeRows expanded = do
  BL.writeFile "imports/latest.csv" expanded
  pure (length (BLC.lines expanded))
