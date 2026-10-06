module OrdersSvc where

import System.Random

resetCode :: IO Int
resetCode = randomRIO (100000, 999999)

endpointPath :: String
endpointPath = "/orders/v0"
