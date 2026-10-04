module Main where

import System.Environment (getEnv)

main :: IO ()
main = do
  dir <- getEnv "MCP_ALLOWED_DIR"
  putStrLn dir
