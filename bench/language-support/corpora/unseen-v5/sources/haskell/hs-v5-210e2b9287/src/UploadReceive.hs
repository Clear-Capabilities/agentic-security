{-# LANGUAGE OverloadedStrings #-}
module UploadReceive (receiveApp) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Lazy.Char8 as BLC
import Data.Time (getCurrentTime)
import Network.HTTP.Types (status200, status405, status413)
import Network.Wai

maxUploadBytes :: Int
maxUploadBytes = 5 * 1024 * 1024

readBounded :: Request -> IO (Maybe BL.ByteString)
readBounded req = go 0 []
  where
    go seen acc = do
      chunk <- getRequestBodyChunk req
      if BS.null chunk
        then pure (Just (BL.fromChunks (reverse acc)))
        else do
          let seen' = seen + BS.length chunk
          if seen' > maxUploadBytes then pure Nothing else go seen' (chunk : acc)

receiveApp :: Application
receiveApp req respond
  | requestMethod req == "POST" = do
      payload <- readBounded req
      case payload of
        Nothing -> respond (responseLBS status413 [] "upload too large")
        Just bytes -> do
          now <- getCurrentTime
          BL.writeFile ("incoming/" <> show now <> ".bin") bytes
          respond (responseLBS status200 [] (BLC.pack ("stored " <> show (BL.length bytes) <> " bytes")))
  | otherwise =
      respond (responseLBS status405 [] "POST only")
