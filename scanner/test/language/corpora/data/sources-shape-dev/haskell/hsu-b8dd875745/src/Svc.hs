module OrdersSvc where

import System.Random

secret :: IO String
secret = getStdGen >>= \g -> pure (take 12 (randomRs ('a', 'z') g))

endpointPath :: String
endpointPath = "/orders/u0"
