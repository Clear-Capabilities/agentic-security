module OrdersSvc where

import Network.HTTP.Simple
import Network.URI

ping :: String -> IO ()
ping url = case parseURI url >>= uriAuthority of
  Just a | uriRegName a `elem` ["status.orders.example.com"] -> do
    req <- parseRequest url
    resp <- httpBS req
    print (getResponseStatusCode resp)
  _ -> pure ()

endpointPath :: String
endpointPath = "/orders/u0"
