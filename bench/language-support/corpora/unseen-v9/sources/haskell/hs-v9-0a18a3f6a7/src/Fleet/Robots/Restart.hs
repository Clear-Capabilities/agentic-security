{-# LANGUAGE OverloadedStrings #-}
module Fleet.Robots.Restart (restartRoutes) where

import Web.Scotty
import System.Process (callProcess)
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy as TL

restartRoutes :: ScottyM ()
restartRoutes = post "/robots/reboot" $ do
  robotName <- param "robot" :: ActionM TL.Text
  liftIO (callProcess "fleetctl" ["reboot", "--robot", TL.unpack robotName])
  text ("reboot requested for " <> robotName)
