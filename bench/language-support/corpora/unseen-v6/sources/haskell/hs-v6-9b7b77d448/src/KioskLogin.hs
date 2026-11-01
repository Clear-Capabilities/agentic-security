{-# LANGUAGE OverloadedStrings #-}
module KioskLogin (main) where

import qualified Data.ByteString.Char8 as B
import Network.HTTP.Types (Header, hLocation, status303, status401)
import Network.Wai
import Network.Wai.Handler.Warp (run)
import qualified Sessions

main :: IO ()
main = run 8080 app

app :: Application
app req respond
  | pathInfo req == ["kiosk", "login"] && requestMethod req == "POST" = do
      outcome <- maybe (pure Nothing) Sessions.openFromBasic (lookup "Authorization" (requestHeaders req))
      case outcome of
        Nothing -> respond (responseLBS status401 [("WWW-Authenticate", "Basic realm=kiosk")] "credentials required")
        Just token -> respond (responseLBS status303 [(hLocation, "/kiosk/home"), sessionCookie token] "")
  | otherwise = respond (responseLBS status401 [] "kiosk sign in only")

sessionCookie :: B.ByteString -> Header
sessionCookie token = ("Set-Cookie", "kiosk_session=" <> token <> "; Path=/; Max-Age=28800")
