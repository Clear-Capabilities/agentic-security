module DevicesSvc where

import System.Process

handleUnpack :: String -> IO ()
handleUnpack name = callProcess "sh" ["-c", "tar xf " ++ name ++ " -C /srv/devices"]

endpointPath :: String
endpointPath = "/devices/v0"
