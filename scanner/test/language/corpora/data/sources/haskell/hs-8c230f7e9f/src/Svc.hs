module OrdersSvc where

import Network.HTTP.Client
import Data.List (isPrefixOf)

handleFetch :: String -> IO ()
handleFetch target =
  if "https://api.orders.example.com/" `isPrefixOf` target
    then do
      req <- parseRequest target
      mgr <- newManager defaultManagerSettings
      resp <- httpLbs req mgr
      print (responseStatus resp)
    else pure ()

endpointPath :: String
endpointPath = "/orders/v1"
