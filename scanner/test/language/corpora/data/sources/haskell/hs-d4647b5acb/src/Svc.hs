module UsersSvc where

import System.Random
import Internal.Users.Policy

handleToken :: Int -> String
handleToken seed = show (fst (randomR (100000, 999999 :: Int) (mkStdGen seed)))

endpointPath :: String
endpointPath = "/users/v0"
