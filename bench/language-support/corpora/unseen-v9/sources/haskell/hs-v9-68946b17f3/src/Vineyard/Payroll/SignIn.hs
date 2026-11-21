{-# LANGUAGE OverloadedStrings #-}
module Vineyard.Payroll.SignIn (signInRoutes) where

import Web.Scotty
import System.Log.FastLogger (LoggerSet, pushLogStrLn, toLogStr)
import Network.HTTP.Types.Status (status401)
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text as T

signInRoutes :: LoggerSet -> (T.Text -> T.Text -> IO Bool) -> ScottyM ()
signInRoutes logger verifyPicker = post "/payroll/login" $ do
  picker <- param "picker" :: ActionM T.Text
  password <- param "password" :: ActionM T.Text
  liftIO (pushLogStrLn logger (toLogStr ("login attempt picker=" <> picker)))
  ok <- liftIO (verifyPicker picker password)
  if ok then text "welcome back" else status status401 >> text "try again"
