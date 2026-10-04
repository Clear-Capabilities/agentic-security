{-# LANGUAGE OverloadedStrings #-}
module Main where

import Network.Wai
import Network.Wai.Handler.Warp (run)
import Network.HTTP.Types (status200, status404)
import Auth (authMiddleware)

router :: Application
router req respond =
  case (requestMethod req, pathInfo req) of
    ("GET", ["health"]) -> respond (responseLBS status200 [] "ok")
    ("POST", ["items"]) -> respond (responseLBS status200 [] "created")
    ("GET", ["items", _]) -> respond (responseLBS status200 [] "item")
    _ -> respond (responseLBS status404 [] "nope")

main :: IO ()
main = run 8080 (authMiddleware router)
