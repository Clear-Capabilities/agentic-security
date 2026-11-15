{-# LANGUAGE OverloadedStrings #-}
module Museum.ImageUpload (imageUploadApp) where

import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import Network.HTTP.Types (status201, status404, status411, status413)
import Network.Wai

maxImageBytes :: Integer
maxImageBytes = 25 * 1024 * 1024

imageUploadApp :: (Text -> BL.ByteString -> IO ()) -> Application
imageUploadApp store req respond =
  case (requestMethod req, pathInfo req, requestBodyLength req) of
    ("PUT", ["objects", accession, "image"], KnownLength n)
      | fromIntegral n <= maxImageBytes -> do
          image <- BL.take (fromIntegral maxImageBytes) <$> lazyRequestBody req
          store accession image
          respond (responseLBS status201 [] "image stored")
      | otherwise -> respond (responseLBS status413 [] "image too large")
    ("PUT", ["objects", _, "image"], ChunkedBody) -> respond (responseLBS status411 [] "length required")
    _ -> respond (responseLBS status404 [] "")
