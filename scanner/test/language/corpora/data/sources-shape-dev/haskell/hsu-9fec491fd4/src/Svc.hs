module OrdersSvc where

import Data.Maybe (fromJust)

lookupKey :: String -> [(String, String)] -> String
lookupKey k env = fromJust (lookup k env)

endpointPath :: String
endpointPath = "/orders/u0"
