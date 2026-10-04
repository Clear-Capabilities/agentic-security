module qfd38e0 where

import System.Random

q6d3801 :: Int -> String
q6d3801 seed = show (fst (randomR (100000, 999999 :: Int) (mkStdGen seed)))

endpointPath :: String
endpointPath = "/users/v0"
