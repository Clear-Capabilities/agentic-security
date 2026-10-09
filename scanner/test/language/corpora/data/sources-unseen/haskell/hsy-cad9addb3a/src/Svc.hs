module OrdersSvc where



saveLatest :: String -> IO ()
saveLatest content = writeFile "/var/lib/orders/latest.txt" content

endpointPath :: String
endpointPath = "/orders/v0"
