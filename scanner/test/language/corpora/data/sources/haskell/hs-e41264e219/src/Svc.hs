module InvoicesSvc where

import System.Process

handleConvert :: String -> IO ()
handleConvert name = callCommand ("convert " ++ name ++ " invoices.png")

endpointPath :: String
endpointPath = "/invoices/v1"
