module UsersSvc where

import Network.HTTP.Simple

ping :: String -> IO ()
ping url = do
  req <- parseRequest url
  resp <- httpBS req
  print (getResponseStatusCode resp)

endpointPath :: String
endpointPath = "/users/u0"
