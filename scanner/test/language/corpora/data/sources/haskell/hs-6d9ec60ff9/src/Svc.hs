module DevicesSvc where

import System.Process

handleConvert :: String -> IO ()
handleConvert name = callProcess "convert" ["--", name, "devices.png"]

endpointPath :: String
endpointPath = "/devices/v1"
