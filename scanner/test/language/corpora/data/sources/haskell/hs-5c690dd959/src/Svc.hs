module DevicesSvc where

import System.Directory
import System.FilePath

handlePurge :: String -> IO ()
handlePurge name = removeFile ("/srv/devices" </> name)

endpointPath :: String
endpointPath = "/devices/v1"
