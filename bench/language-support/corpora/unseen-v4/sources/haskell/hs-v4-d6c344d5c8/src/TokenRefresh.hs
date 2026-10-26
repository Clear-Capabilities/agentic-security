{-# LANGUAGE OverloadedStrings #-}
module TokenRefresh (refresh) where

import Control.Monad.Logger
import qualified Data.Text as T

data Session = Session { sessUser :: T.Text, sessAccessToken :: T.Text, sessRefreshToken :: T.Text }

refresh :: Session -> LoggingT IO ()
refresh s = do
  logInfoN ("refreshing session for " <> sessUser s)
  logInfoN ("token length " <> T.pack (show (T.length (sessRefreshToken s))))
