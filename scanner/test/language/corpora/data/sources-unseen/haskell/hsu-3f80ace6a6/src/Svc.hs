module UsersSvc where



journal :: String -> IO ()
journal secret = appendFile "users-journal.log" ("secret: " ++ secret ++ "\n")

endpointPath :: String
endpointPath = "/users/u0"
