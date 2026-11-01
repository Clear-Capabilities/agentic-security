{-# LANGUAGE OverloadedStrings #-}
module SignInAudit (main) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy as TL
import System.Log.FastLogger
import Web.Scotty
import qualified Directory

main :: IO ()
main = do
  logger <- newStdoutLoggerSet defaultBufSize
  scotty 8080 $
    post "/login" $ do
      user <- param "user"
      password <- param "password"
      accepted <- liftIO (Directory.verify user password)
      liftIO (pushLogStrLn logger (toLogStr ("login attempt user=" <> user <> " accepted=" <> TL.pack (show accepted))))
      if accepted
        then text "welcome"
        else text "try again"
