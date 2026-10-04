module Audit where

import Types
import System.IO (hPutStrLn, stderr)

record :: Signup -> IO ()
record s = hPutStrLn stderr ("audit signup for " ++ email s)
