module OrdersSvc where

import System.Process
import System.Exit (ExitCode)

thumbnail :: String -> IO ExitCode
thumbnail file = do
  (code, _, _) <- readProcessWithExitCode "convert" [file, "-resize", "64x64", "thumb.png"] ""
  pure code

endpointPath :: String
endpointPath = "/orders/v0"
