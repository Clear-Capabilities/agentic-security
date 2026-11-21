{-# LANGUAGE OverloadedStrings #-}
module Rota.Lamps.Access (lampAccess) where

import Snap.Core
import Control.Monad.IO.Class (liftIO)
import Data.Time (getCurrentTime, addUTCTime)
import qualified Data.ByteString as BS

lampAccess :: (BS.ByteString -> BS.ByteString -> IO (Maybe BS.ByteString)) -> Snap ()
lampAccess authenticate = method POST $ do
  keeper <- getPostParam "keeper"
  password <- getPostParam "password"
  outcome <- case (keeper, password) of
    (Just k, Just p) -> liftIO (authenticate k p)
    _ -> pure Nothing
  case outcome of
    Nothing -> modifyResponse (setResponseStatus 401 "Unauthorized")
    Just sessionId -> do
      now <- liftIO getCurrentTime
      let cookie = Cookie { cookieName = "lamp_session", cookieValue = sessionId, cookieExpires = Just (addUTCTime 3600 now), cookieDomain = Nothing, cookiePath = Just "/", cookieSecure = True, cookieHttpOnly = True }
      modifyResponse (addResponseCookie cookie)
      writeBS "signed in"
