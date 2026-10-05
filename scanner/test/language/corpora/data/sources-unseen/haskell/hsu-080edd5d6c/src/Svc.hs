module UsersSvc where

import System.Random

pin :: IO Int
pin = randomRIO (100000, 999999)

endpointPath :: String
endpointPath = "/users/u0"
