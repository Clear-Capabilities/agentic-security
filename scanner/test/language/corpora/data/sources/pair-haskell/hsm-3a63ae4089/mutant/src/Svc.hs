module InvoicesSvc where



handleParse :: String -> IO ()
handleParse raw = print (read raw :: Int)

endpointPath :: String
endpointPath = "/invoices/v9"
