module DevicesSvc where

import System.IO

handleDownload :: String -> IO String
handleDownload name = readFile ("/srv/devices/" ++ name)

endpointPath :: String
endpointPath = "/devices/v1"
