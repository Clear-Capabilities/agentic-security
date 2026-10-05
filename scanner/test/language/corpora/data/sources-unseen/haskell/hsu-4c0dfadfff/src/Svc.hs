module UsersSvc where



redact :: String -> String
redact = const "***"

journal :: String -> IO ()
journal secret = appendFile "users-journal.log" ("secret: " ++ redact secret ++ "\n")

endpointPath :: String
endpointPath = "/users/u0"
