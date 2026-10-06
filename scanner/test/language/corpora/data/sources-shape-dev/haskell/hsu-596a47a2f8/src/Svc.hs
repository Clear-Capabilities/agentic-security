module OrdersSvc where



slurpBytes :: IO String
slurpBytes = fmap (take 4096) getContents

endpointPath :: String
endpointPath = "/orders/u0"
