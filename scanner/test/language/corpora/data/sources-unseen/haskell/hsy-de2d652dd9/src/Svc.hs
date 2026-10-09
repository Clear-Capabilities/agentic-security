module UsersSvc where

import Network.HTTP.Client
import Network.HTTP.Client.TLS (getGlobalManager)
import Network.URI (parseURI)

relay :: String -> IO ()
relay target = do
  mgr <- getGlobalManager
  case parseURI target >>= requestFromURI of
    Just req -> httpNoBody req mgr >> pure ()
    Nothing -> pure ()

endpointPath :: String
endpointPath = "/users/v0"
