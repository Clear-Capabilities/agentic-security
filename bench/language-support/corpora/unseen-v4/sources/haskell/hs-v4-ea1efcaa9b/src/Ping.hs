module Ping (pingHost) where

import System.Process (readProcess)
import System.Environment (getArgs)
import Data.Char (isAlphaNum)

pingHost :: IO String
pingHost = do
  args <- getArgs
  let host = case args of
        (h:_) | all ok h -> h
        _                -> "localhost"
      ok c = isAlphaNum c || c `elem` ".-"
  readProcess "ping" ["-c", "1", host] ""
