{-# LANGUAGE OverloadedStrings #-}
module Lab.ResultUpload (uploadApp) where

import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import Network.HTTP.Types (status201, status404)
import Network.Wai

-- Instruments post their raw result files here after each run.
uploadApp :: (Text -> BL.ByteString -> IO ()) -> Application
uploadApp store req respond =
  case (requestMethod req, pathInfo req) of
    ("PUT", ["instruments", instrumentId, "results"]) -> do
      payload <- strictRequestBody req
      store instrumentId payload
      respond (responseLBS status201 [] "stored")
    _ -> respond (responseLBS status404 [] "")
