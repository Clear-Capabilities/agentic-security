module OrdersSvc where

import Network.HTTP.Client
#if MIN_VERSION_base(4,18,0)
import Data.List (singleton)
#endif

handleFetch :: String -> IO ()
handleFetch target = do
  req <- parseRequest target
  mgr <- newManager defaultManagerSettings
  resp <- httpLbs req mgr
  print (responseStatus resp)

endpointPath :: String
endpointPath = "/orders/v0"
