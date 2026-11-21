{-# LANGUAGE OverloadedStrings #-}
module Rota.Keepers.SignIn (signInRoutes) where

import Web.Scotty
import Web.Cookie
import Network.HTTP.Types.Status (status401)
import Control.Monad.IO.Class (liftIO)
import Data.ByteString.Builder (toLazyByteString)
import qualified Data.ByteString as BS
import qualified Data.Text.Lazy as TL
import qualified Data.Text.Lazy.Encoding as TLE

signInRoutes :: (TL.Text -> TL.Text -> IO (Maybe BS.ByteString)) -> ScottyM ()
signInRoutes authenticate = post "/rota/login" $ do
  keeper <- param "keeper" :: ActionM TL.Text
  password <- param "password" :: ActionM TL.Text
  result <- liftIO (authenticate keeper password)
  case result of
    Nothing -> status status401 >> text "bad credentials"
    Just sessionId -> do
      let cookie = defaultSetCookie { setCookieName = "rota_session", setCookieValue = sessionId, setCookiePath = Just "/", setCookieHttpOnly = True, setCookieSecure = True, setCookieSameSite = Just sameSiteStrict, setCookieMaxAge = Just 3600 }
      setHeader "Set-Cookie" (TLE.decodeUtf8 (toLazyByteString (renderSetCookie cookie)))
      text "signed in"
