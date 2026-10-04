module DevicesSvc where

import System.Directory
import System.FilePath

handlePurge :: String -> IO ()
handlePurge name =
  if ".." `elem` splitDirectories name
    then pure ()
    else removeFile ("/srv/devices" </> name)

endpointPath :: String
endpointPath = "/devices/v1"
