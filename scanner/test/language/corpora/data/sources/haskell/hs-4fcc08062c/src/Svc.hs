module TicketsSvc where

import Network.HTTP.Client

allowedHosts :: [String]
allowedHosts = ["https://hooks.tickets.example.com/ping"]

handleProbe :: String -> IO ()
handleProbe target =
  if target `elem` allowedHosts
    then do
      req <- parseUrlThrow target
      mgr <- newManager defaultManagerSettings
      body <- httpLbs req mgr
      print (responseBody body)
    else pure ()

endpointPath :: String
endpointPath = "/tickets/v1"
