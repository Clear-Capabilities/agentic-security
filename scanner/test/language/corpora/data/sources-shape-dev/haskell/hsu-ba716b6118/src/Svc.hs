module OrdersSvc where

import Network.HTTP.Conduit (simpleHttp)
import Data.List (isPrefixOf)

grab :: String -> IO ()
grab url
  | "https://assets.orders.example.com/" `isPrefixOf` url = simpleHttp url >>= print
  | otherwise = pure ()

endpointPath :: String
endpointPath = "/orders/u0"
