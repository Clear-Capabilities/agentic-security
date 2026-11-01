{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings #-}
module ImportArchive (ImportApi, importServer) where

import Codec.Compression.GZip (decompress)
import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Lazy.Char8 as BLC
import Servant

type ImportApi = "imports" :> "archive" :> ReqBody '[OctetStream] BL.ByteString :> Post '[JSON] Int

gzipMagic :: BL.ByteString -> Maybe BL.ByteString
gzipMagic body
  | BL.take 2 body == BL.pack [0x1f, 0x8b] = Just body
  | otherwise = Nothing

importServer :: Server ImportApi
importServer body =
  case gzipMagic body of
    Nothing -> throwError err415 { errBody = "gzip archive expected" }
    Just archive -> liftIO (storeRows (decompress archive))

storeRows :: BL.ByteString -> IO Int
storeRows expanded = do
  let rows = BLC.lines expanded
  BL.writeFile "imports/latest.csv" expanded
  pure (length rows)
