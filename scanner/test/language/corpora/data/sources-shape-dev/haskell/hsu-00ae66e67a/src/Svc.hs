module UsersSvc where

import System.Random

secret :: IO String
secret = getStdGen >>= \g -> pure (take 12 (randomRs ('a', 'z') g))

endpointPath :: String
endpointPath = "/users/u0"
