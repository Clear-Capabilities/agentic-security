module OrdersSvc where

import Network.HTTP.Simple

fetch :: Int -> IO ()
fetch itemId = do
  req <- parseRequest ("https://api.orders.example.com/items/" ++ show itemId)
  resp <- httpBS req
  print (getResponseStatusCode resp)

endpointPath :: String
endpointPath = "/orders/v0"
