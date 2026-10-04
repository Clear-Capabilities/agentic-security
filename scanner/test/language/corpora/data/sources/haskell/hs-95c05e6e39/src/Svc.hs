module OrdersSvc where



handleBanner :: String -> IO ()
handleBanner url = putStrLn ("<a href='" ++ url ++ "'>orders</a>")

endpointPath :: String
endpointPath = "/orders/v1"
