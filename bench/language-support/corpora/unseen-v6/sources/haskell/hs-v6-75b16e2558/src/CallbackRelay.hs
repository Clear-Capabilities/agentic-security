{-# LANGUAGE OverloadedStrings #-}
module CallbackRelay (main) where

import qualified Data.ByteString.Char8 as B
import Network.HTTP.Simple
import Network.HTTP.Types (status200, status400)
import Network.Wai
import Network.Wai.Handler.Warp (run)

main :: IO ()
main = run 8080 relay

relay :: Application
relay req respond =
  case lookup "X-Callback-Host" (requestHeaders req) of
    Nothing -> respond (responseLBS status400 [] "callback host header required")
    Just callbackHost -> do
      let target = setRequestHost callbackHost
                 $ setRequestPath "/relay/receive"
                 $ setRequestMethod "POST"
                 $ setRequestBodyLBS "ping" defaultRequest
      upstream <- httpLBS target
      respond (responseLBS status200 [("Content-Type", "text/plain")] (getResponseBody upstream))
