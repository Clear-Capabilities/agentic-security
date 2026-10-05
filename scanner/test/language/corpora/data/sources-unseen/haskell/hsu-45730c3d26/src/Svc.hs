module OrdersSvc where

import Network.HTTP.Simple

ping :: String -> IO ()
ping url = do
  req <- parseRequest url
  resp <- httpBS req
  print (getResponseStatusCode resp)

endpointPath :: String
endpointPath = "/orders/u0"
