{-# LANGUAGE OverloadedStrings #-}
module Ferry.CrewLogin (crewLoginApp) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Builder as B
import qualified Data.ByteString.Lazy as BL
import Network.HTTP.Types (hAuthorization, hSetCookie, status200, status401, status405)
import Network.Wai
import Web.Cookie

crewCookie :: ByteString -> SetCookie
crewCookie sid = defaultSetCookie
  { setCookieName = "crew_session"
  , setCookieValue = sid
  , setCookiePath = Just "/"
  , setCookieHttpOnly = True
  , setCookieSecure = True
  , setCookieSameSite = Just sameSiteStrict
  , setCookieMaxAge = Just 28800
  }

renderCookie :: SetCookie -> ByteString
renderCookie = BL.toStrict . B.toLazyByteString . renderSetCookie

crewLoginApp :: (ByteString -> IO (Maybe ByteString)) -> Application
crewLoginApp authenticate req respond
  | requestMethod req /= "POST" = respond (responseLBS status405 [] "")
  | otherwise = do
      result <- maybe (pure Nothing) authenticate (lookup hAuthorization (requestHeaders req))
      case result of
        Nothing -> respond (responseLBS status401 [("WWW-Authenticate", "Basic realm=\"crew\"")] "crew login failed")
        Just sid -> respond (responseLBS status200 [(hSetCookie, renderCookie (crewCookie sid))] "welcome aboard")
