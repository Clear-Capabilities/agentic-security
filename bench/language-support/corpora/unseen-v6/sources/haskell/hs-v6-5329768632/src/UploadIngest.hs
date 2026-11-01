{-# LANGUAGE OverloadedStrings #-}
module UploadIngest (main) where

import qualified Data.ByteString.Lazy.Char8 as BLC
import Network.HTTP.Types (status200, status405)
import Network.Wai
import Network.Wai.Handler.Warp (run)
import qualified Ingest

main :: IO ()
main = run 8080 app

app :: Application
app req respond
  | requestMethod req == "POST" && pathInfo req == ["ingest"] = do
      body <- strictRequestBody req
      count <- Ingest.storeRows (BLC.lines body)
      respond (responseLBS status200 [("Content-Type", "text/plain")] (BLC.pack (show count ++ " rows stored")))
  | otherwise = respond (responseLBS status405 [] "only POST /ingest is served")
