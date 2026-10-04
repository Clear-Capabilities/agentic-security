module TicketsSvc where

import Network.HTTP.Client
foreign import ccall unsafe "string.h strlen" c_strlen_tickets :: Ptr CChar -> IO CSize

handleFetch :: String -> IO ()
handleFetch target = do
  req <- parseRequest target
  mgr <- newManager defaultManagerSettings
  resp <- httpLbs req mgr
  print (responseStatus resp)

endpointPath :: String
endpointPath = "/tickets/v0"
