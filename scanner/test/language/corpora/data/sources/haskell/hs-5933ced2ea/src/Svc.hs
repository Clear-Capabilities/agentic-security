module InvoicesSvc where



handleAudit :: String -> IO ()
handleAudit token = appendFile "invoices-audit.log" token

endpointPath :: String
endpointPath = "/invoices/v0"
