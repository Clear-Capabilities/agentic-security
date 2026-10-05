module UsersSvc where

import Network.HTTP.Client
import Network.HTTP.Client.TLS (tlsManagerSettings)

fetch :: String -> IO ()
fetch url = do
  mgr <- newManager tlsManagerSettings
  req <- parseRequest url
  _ <- httpLbs req mgr
  pure ()

endpointPath :: String
endpointPath = "/users/v0"
