module UsersSvc where

import Data.Maybe (fromJust)

setting :: String -> [(String, String)] -> String
setting key table = fromJust (lookup key table)

endpointPath :: String
endpointPath = "/users/v0"
