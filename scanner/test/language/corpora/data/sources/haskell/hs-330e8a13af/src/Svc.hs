module UsersSvc where



handleAllocate :: String -> String
handleAllocate raw = replicate (read raw :: Int) 'x'

endpointPath :: String
endpointPath = "/users/v0"
