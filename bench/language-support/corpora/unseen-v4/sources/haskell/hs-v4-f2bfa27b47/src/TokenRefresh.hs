{-# LANGUAGE OverloadedStrings #-}
module TokenRefresh (refresh) where

import Control.Monad.Logger
import qualified Data.Text as T

data Session = Session { sessUser :: T.Text, sessAccessToken :: T.Text, sessRefreshToken :: T.Text }

refresh :: Session -> LoggingT IO ()
refresh s = do
  logInfoN ("refreshing session " <> T.pack (show (sessRefreshToken s)))
  logInfoN ("user " <> sessUser s)
