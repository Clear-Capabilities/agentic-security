module DevicesSvc where

import System.Random

handleToken :: Int -> String
handleToken seed = show (fst (randomR (100000, 999999 :: Int) (mkStdGen seed)))

endpointPath :: String
endpointPath = "/devices/v0"
