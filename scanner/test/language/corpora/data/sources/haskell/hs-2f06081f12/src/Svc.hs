module UsersSvc where



handleAllocate :: String -> String
handleAllocate raw = replicate (min 4096 (read raw :: Int)) 'x'

endpointPath :: String
endpointPath = "/users/v1"
