{-# LANGUAGE OverloadedStrings #-}
module UploadIngest (ingestApp) where

import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Lazy.Char8 as BLC
import Data.Time (getCurrentTime)
import Network.HTTP.Types (status200, status405)
import Network.Wai

data Upload = Upload { uploadName :: FilePath, uploadBytes :: BL.ByteString }

ingestApp :: Application
ingestApp req respond
  | requestMethod req == "POST" = do
      payload <- strictRequestBody req
      now <- getCurrentTime
      let upload = Upload ("incoming/" <> show now <> ".bin") payload
      BL.writeFile (uploadName upload) (uploadBytes upload)
      respond (responseLBS status200 [] (BLC.pack ("stored " <> show (BL.length payload) <> " bytes")))
  | otherwise =
      respond (responseLBS status405 [] "POST only")
