module OrdersSvc where

import Network.HTTP.Conduit (simpleHttp)

fetch :: String -> IO ()
fetch url = if url `elem` ["https://status.orders.example.com/health", "https://status.orders.example.com/ready"] then simpleHttp url >>= print else pure ()

endpointPath :: String
endpointPath = "/orders/v0"
