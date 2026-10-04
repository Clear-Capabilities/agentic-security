module InvoicesSvc where



redact :: String -> String
redact _ = "***"

handleAudit :: String -> IO ()
handleAudit token = appendFile "invoices-audit.log" (redact token)

endpointPath :: String
endpointPath = "/invoices/v1"
