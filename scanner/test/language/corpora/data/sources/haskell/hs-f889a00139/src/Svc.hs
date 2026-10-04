module DevicesSvc where

import Text.Read (readMaybe)

handleParse :: String -> IO ()
handleParse raw = print (readMaybe raw :: Maybe Int)

endpointPath :: String
endpointPath = "/devices/v0"
