module UsersSvc where



slurpBytes :: IO String
slurpBytes = fmap (take 4096) getContents

endpointPath :: String
endpointPath = "/users/u0"
