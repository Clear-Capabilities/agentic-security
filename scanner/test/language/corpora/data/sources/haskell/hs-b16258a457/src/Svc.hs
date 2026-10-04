module UsersSvc where



handleAudit :: String -> IO ()
handleAudit token = appendFile "users-audit.log" token

endpointPath :: String
endpointPath = "/users/v1"
