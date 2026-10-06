module OrdersSvc where

import Network.HTTP.Conduit (simpleHttp)
import Data.List (isPrefixOf)

ping :: String -> IO ()
ping url
  | "https://hooks.orders.example.com/" `isPrefixOf` url = simpleHttp url >>= print
  | otherwise = ioError (userError "host not allowed")

endpointPath :: String
endpointPath = "/orders/v0"
