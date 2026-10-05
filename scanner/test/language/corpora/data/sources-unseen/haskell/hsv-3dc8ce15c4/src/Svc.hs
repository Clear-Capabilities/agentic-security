module OrdersSvc where

import Network.HTTP.Conduit

ping :: String -> IO ()
ping url = parseUrlThrow url >>= \req -> newManager tlsManagerSettings >>= httpNoBody req >> pure ()

endpointPath :: String
endpointPath = "/orders/v0"
