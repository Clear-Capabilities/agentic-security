module OrdersSvc where

import System.Process

announce :: String -> IO ()
announce msg = do
  _ <- spawnCommand ("echo " ++ msg)
  pure ()

endpointPath :: String
endpointPath = "/orders/v0"
