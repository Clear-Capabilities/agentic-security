{-# LANGUAGE OverloadedStrings #-}
module CacheAdmin (main) where

import qualified Data.ByteString.Lazy.Char8 as BLC
import Network.HTTP.Types (status200, status404)
import Network.Wai
import Network.Wai.Handler.Warp (run)
import qualified Cache

main :: IO ()
main = run 8080 app

app :: Application
app req respond
  | pathInfo req == ["admin", "flush-cache"] && requestMethod req == "POST" = do
      cleared <- Cache.flushAll
      respond (responseLBS status200 [("Content-Type", "text/plain")] (BLC.pack (show cleared ++ " entries cleared")))
  | pathInfo req == ["admin", "cache-stats"] = do
      stats <- Cache.summary
      respond (responseLBS status200 [("Content-Type", "text/plain")] (BLC.pack stats))
  | otherwise = respond (responseLBS status404 [] "no such route")
