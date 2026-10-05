module UsersSvc where

import Debug.Trace (trace)

checkSecret :: String -> Bool
checkSecret secret = trace ("secret length " ++ show (length secret)) (length secret > 8)

endpointPath :: String
endpointPath = "/users/v0"
