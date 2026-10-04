module UsersSvc where

import Network.HTTP.Client
class Sink a where
  emitUsers :: a -> IO ()

handleFetch :: String -> IO ()
handleFetch target = do
  req <- parseRequest target
  mgr <- newManager defaultManagerSettings
  resp <- httpLbs req mgr
  print (responseStatus resp)

endpointPath :: String
endpointPath = "/users/v0"
