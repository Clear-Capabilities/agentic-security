{-# LANGUAGE OverloadedStrings #-}
module Orchard.Drones.Ingest (ingestApp) where

import Network.Wai
import Network.HTTP.Types (status201, status405, status413)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL

maxFrameBytes :: Int
maxFrameBytes = 8 * 1024 * 1024

readCapped :: Int -> Request -> IO (Maybe BL.ByteString)
readCapped limit req = go 0 []
  where
    go total acc = do
      chunk <- getRequestBodyChunk req
      if BS.null chunk
        then pure (Just (BL.fromChunks (reverse acc)))
        else
          let total' = total + BS.length chunk
          in if total' > limit then pure Nothing else go total' (chunk : acc)

ingestApp :: (BL.ByteString -> IO ()) -> Application
ingestApp storeFrame req respond
  | requestMethod req /= "PUT" = respond (responseLBS status405 [] "frames are uploaded with PUT")
  | otherwise = do
      body <- readCapped maxFrameBytes req
      case body of
        Nothing -> respond (responseLBS status413 [] "frame larger than 8 MiB")
        Just frame -> do
          storeFrame frame
          respond (responseLBS status201 [] "frame stored")
