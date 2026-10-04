module TicketsSvc where

import Network.HTTP.Client

handleProbe :: String -> IO ()
handleProbe target = do
  req <- parseUrlThrow target
  mgr <- newManager defaultManagerSettings
  body <- httpLbs req mgr
  print (responseBody body)

endpointPath :: String
endpointPath = "/tickets/v1"
