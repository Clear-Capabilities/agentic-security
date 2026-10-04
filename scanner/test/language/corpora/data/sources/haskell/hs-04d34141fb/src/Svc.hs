module UsersSvc where



redact :: String -> String
redact _ = "***"

handleAudit :: String -> IO ()
handleAudit token = appendFile "users-audit.log" (redact token)

endpointPath :: String
endpointPath = "/users/v1"
