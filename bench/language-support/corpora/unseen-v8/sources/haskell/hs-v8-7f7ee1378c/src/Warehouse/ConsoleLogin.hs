{-# LANGUAGE OverloadedStrings #-}
module Warehouse.ConsoleLogin (consoleLogin) where

import Control.Monad.IO.Class (liftIO)
import Data.ByteString (ByteString)
import Snap.Core

consoleCookie :: ByteString -> Cookie
consoleCookie sid = Cookie
  { cookieName = "console_session"
  , cookieValue = sid
  , cookieExpires = Nothing
  , cookieDomain = Nothing
  , cookiePath = Just "/"
  , cookieSecure = True
  , cookieHttpOnly = True
  }

consoleLogin :: (ByteString -> ByteString -> IO (Maybe ByteString)) -> Snap ()
consoleLogin authenticate = method POST $ do
  mBadge <- getPostParam "badge"
  mPin <- getPostParam "pin"
  case (mBadge, mPin) of
    (Just badge, Just pin) -> do
      r <- liftIO (authenticate badge pin)
      case r of
        Just sid -> modifyResponse (addResponseCookie (consoleCookie sid)) >> redirect "/console"
        Nothing -> modifyResponse (setResponseStatus 401 "Unauthorized") >> writeBS "login refused"
    _ -> modifyResponse (setResponseStatus 400 "Bad Request") >> writeBS "badge and pin required"
