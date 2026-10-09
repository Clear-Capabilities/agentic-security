module UsersSvc where

import System.Random (randomRIO)
import Control.Monad (replicateM)

temporaryPassword :: IO String
temporaryPassword = replicateM 12 (randomRIO ('a', 'z'))

endpointPath :: String
endpointPath = "/users/v0"
