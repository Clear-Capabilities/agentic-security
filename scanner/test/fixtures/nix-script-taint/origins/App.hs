module App where

import System.Environment (getEnv)
import System.Process (callCommand)

main :: IO ()
main = do
  target <- getEnv "APP_TARGET"
  callCommand ("rm -rf " ++ target)
