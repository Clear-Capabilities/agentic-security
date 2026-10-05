module UsersSvc where

import Data.Maybe (fromJust)

lookupKey :: String -> [(String, String)] -> String
lookupKey k env = fromJust (lookup k env)

endpointPath :: String
endpointPath = "/users/u0"
