module UsersSvc where

import System.Random (randomRIO)
import Control.Concurrent (threadDelay)

retryJitter :: IO ()
retryJitter = randomRIO (50, 250) >>= \ms -> threadDelay (ms * 1000)

endpointPath :: String
endpointPath = "/users/v0"
