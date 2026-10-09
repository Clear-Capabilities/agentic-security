module UsersSvc where



saveLatest :: String -> IO ()
saveLatest content = writeFile "/var/lib/users/latest.txt" content

endpointPath :: String
endpointPath = "/users/v0"
