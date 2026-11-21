{-# LANGUAGE OverloadedStrings #-}
module Fleet.Telemetry.Probe (probeRobot) where

import Turtle

probeRobot :: IO ()
probeRobot = do
  configured <- need "ROBOT_HOST"
  case configured of
    Nothing -> die "ROBOT_HOST is not set"
    Just robotHost -> do
      shells ("ping -c 3 " <> robotHost) empty
      echo "robot reachable"
