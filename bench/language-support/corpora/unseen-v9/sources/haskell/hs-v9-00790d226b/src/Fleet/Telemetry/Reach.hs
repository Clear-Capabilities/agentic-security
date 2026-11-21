{-# LANGUAGE OverloadedStrings #-}
module Fleet.Telemetry.Reach (reachRobot) where

import Turtle

reachRobot :: IO ()
reachRobot = do
  configured <- need "ROBOT_HOST"
  case configured of
    Nothing -> die "ROBOT_HOST is not set"
    Just robotHost -> do
      procs "ping" ["-c", "3", robotHost] empty
      echo "robot reachable"
