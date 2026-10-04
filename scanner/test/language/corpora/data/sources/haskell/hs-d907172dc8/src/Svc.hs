module DevicesSvc where



handleBanner :: String -> IO ()
handleBanner url = putStrLn ("<a href='" ++ url ++ "'>devices</a>")

endpointPath :: String
endpointPath = "/devices/v1"
