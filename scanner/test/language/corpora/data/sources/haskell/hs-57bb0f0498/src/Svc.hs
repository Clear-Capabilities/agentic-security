module InvoicesSvc where



handleBanner :: String -> IO ()
handleBanner url = putStrLn ("<a href='" ++ url ++ "'>invoices</a>")

endpointPath :: String
endpointPath = "/invoices/v0"
