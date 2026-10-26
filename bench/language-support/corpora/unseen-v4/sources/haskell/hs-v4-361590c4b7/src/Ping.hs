module Ping (pingHost) where

import System.Process (readProcess)
import System.Environment (getArgs)

pingHost :: IO String
pingHost = do
  args <- getArgs
  let host = case args of
        (h:_) -> h
        []    -> "localhost"
  readProcess "sh" ["-c", "ping -c 1 " ++ host] ""
