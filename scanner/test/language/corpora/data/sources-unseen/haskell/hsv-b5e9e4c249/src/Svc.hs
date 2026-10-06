module UsersSvc where

import System.Random

resetCode :: IO Int
resetCode = randomRIO (100000, 999999)

endpointPath :: String
endpointPath = "/users/v0"
