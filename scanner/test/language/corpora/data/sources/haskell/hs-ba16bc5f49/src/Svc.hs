module DevicesSvc where



redact :: String -> String
redact _ = "***"

handleAudit :: String -> IO ()
handleAudit token = appendFile "devices-audit.log" (redact token)

endpointPath :: String
endpointPath = "/devices/v1"
