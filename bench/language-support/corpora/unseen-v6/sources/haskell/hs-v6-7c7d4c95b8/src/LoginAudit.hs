{-# LANGUAGE OverloadedStrings #-}
module LoginAudit (main) where

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
      liftIO (pushLogStrLn logger (toLogStr ("login attempt user=" <> user <> " password=" <> password :: TL.Text)))
      accepted <- liftIO (Directory.verify user password)
      if accepted
        then text "welcome"
        else text "try again"
