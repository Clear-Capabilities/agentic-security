module InvoicesSvc where



handleFirst :: String -> String
handleFirst raw = head (words raw)

endpointPath :: String
endpointPath = "/invoices/v1"
