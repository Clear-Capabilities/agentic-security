module UsersSvc where



handleBanner :: String -> IO ()
handleBanner url = putStrLn ("<a href='" ++ url ++ "'>users</a>")

endpointPath :: String
endpointPath = "/users/v0"
