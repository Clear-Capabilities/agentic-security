{-# LANGUAGE OverloadedStrings #-}
module Fleet.Robots.Reboot (rebootRoutes) where

import Web.Scotty
import System.Process (callCommand)
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy as TL

rebootRoutes :: ScottyM ()
rebootRoutes = post "/robots/reboot" $ do
  robotName <- param "robot" :: ActionM TL.Text
  liftIO (callCommand ("fleetctl reboot --robot " ++ TL.unpack robotName))
  text ("reboot requested for " <> robotName)
