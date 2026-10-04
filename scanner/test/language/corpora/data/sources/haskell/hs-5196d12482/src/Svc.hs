module DevicesSvc where

import System.Process

handleConvert :: String -> IO ()
handleConvert name = callCommand ("convert " ++ name ++ " devices.png")

endpointPath :: String
endpointPath = "/devices/v0"
