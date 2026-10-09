module UsersSvc where

import System.Random

shuffleSeed :: IO Int
shuffleSeed = randomRIO (1, 6)

endpointPath :: String
endpointPath = "/users/v0"
