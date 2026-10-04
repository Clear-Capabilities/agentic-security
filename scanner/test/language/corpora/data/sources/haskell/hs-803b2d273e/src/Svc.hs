module DevicesSvc where



handleAudit :: String -> IO ()
handleAudit token = appendFile "devices-audit.log" token

endpointPath :: String
endpointPath = "/devices/v0"
