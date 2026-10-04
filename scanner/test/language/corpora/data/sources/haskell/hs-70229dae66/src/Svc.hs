module DevicesSvc where



handleFirst :: String -> String
handleFirst raw = head (words raw)

endpointPath :: String
endpointPath = "/devices/v1"
