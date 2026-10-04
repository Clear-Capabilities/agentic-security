module InvoicesSvc where

import Network.HTTP.Client
import Data.List (isPrefixOf)

handleFetch :: String -> IO ()
handleFetch target =
  if "https://api.invoices.example.com/" `isPrefixOf` target
    then do
      req <- parseRequest target
      mgr <- newManager defaultManagerSettings
      resp <- httpLbs req mgr
      print (responseStatus resp)
    else pure ()

endpointPath :: String
endpointPath = "/invoices/v0"
