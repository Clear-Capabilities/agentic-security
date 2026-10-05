module OrdersSvc where

import Network.HTTP.Conduit (simpleHttp)

grab :: String -> IO ()
grab url = simpleHttp url >>= print

endpointPath :: String
endpointPath = "/orders/u0"
