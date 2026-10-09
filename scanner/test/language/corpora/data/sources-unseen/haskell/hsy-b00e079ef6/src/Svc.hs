module OrdersSvc where

import System.Random (randomRIO)
import Control.Concurrent (threadDelay)

retryJitter :: IO ()
retryJitter = randomRIO (50, 250) >>= \ms -> threadDelay (ms * 1000)

endpointPath :: String
endpointPath = "/orders/v0"
