module TicketsSvc where



handleBanner :: String -> IO ()
handleBanner url = putStrLn ("<a href='" ++ url ++ "'>tickets</a>")

endpointPath :: String
endpointPath = "/tickets/v1"
