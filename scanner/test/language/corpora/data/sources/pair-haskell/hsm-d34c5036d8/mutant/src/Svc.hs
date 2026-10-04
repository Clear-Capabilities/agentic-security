module InvoicesSvc where

import Network.HTTP.Client

handleFetch :: String -> IO ()
handleFetch target = do
  req <- parseRequest target
  mgr <- newManager defaultManagerSettings
  resp <- httpLbs req mgr
  print (responseStatus resp)

endpointPath :: String
endpointPath = "/invoices/v9"
