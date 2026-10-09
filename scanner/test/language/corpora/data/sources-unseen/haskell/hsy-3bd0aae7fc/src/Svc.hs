module OrdersSvc where

import System.Random (randomRIO)
import Control.Monad (replicateM)

temporaryPassword :: IO String
temporaryPassword = replicateM 12 (randomRIO ('a', 'z'))

endpointPath :: String
endpointPath = "/orders/v0"
