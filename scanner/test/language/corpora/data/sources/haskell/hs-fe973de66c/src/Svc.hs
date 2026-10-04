module DevicesSvc where



handleAllocate :: String -> String
handleAllocate raw = replicate (read raw :: Int) 'x'

endpointPath :: String
endpointPath = "/devices/v0"
