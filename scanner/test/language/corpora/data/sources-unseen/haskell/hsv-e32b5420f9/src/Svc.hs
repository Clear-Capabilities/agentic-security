module OrdersSvc where

import Debug.Trace (trace)

checkSecret :: String -> Bool
checkSecret secret = trace ("secret was " ++ secret) (length secret > 8)

endpointPath :: String
endpointPath = "/orders/v0"
