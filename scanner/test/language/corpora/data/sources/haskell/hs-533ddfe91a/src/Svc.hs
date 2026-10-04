module DevicesSvc where

import System.IO
import System.FilePath (takeFileName)

handleDownload :: String -> IO String
handleDownload name = readFile ("/srv/devices/" ++ takeFileName name)

endpointPath :: String
endpointPath = "/devices/v0"
