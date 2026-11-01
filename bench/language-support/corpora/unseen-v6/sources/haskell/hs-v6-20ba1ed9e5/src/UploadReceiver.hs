{-# LANGUAGE OverloadedStrings #-}
module UploadReceiver (main) where

import qualified Data.ByteString.Lazy.Char8 as BLC
import Network.HTTP.Types (status200, status405, status413)
import Network.Wai
import Network.Wai.Handler.Warp (run)
import qualified Ingest

maxBytes :: Integer
maxBytes = 1024 * 1024

main :: IO ()
main = run 8080 app

app :: Application
app req respond
  | requestMethod req == "POST" && pathInfo req == ["ingest"] =
      case requestBodyLength req of
        KnownLength n | fromIntegral n <= maxBytes -> do
          body <- strictRequestBody req
          count <- Ingest.storeRows (BLC.lines body)
          respond (responseLBS status200 [("Content-Type", "text/plain")] (BLC.pack (show count ++ " rows stored")))
        _ -> respond (responseLBS status413 [] "body must declare a length of at most 1 MiB")
  | otherwise = respond (responseLBS status405 [] "only POST /ingest is served")
