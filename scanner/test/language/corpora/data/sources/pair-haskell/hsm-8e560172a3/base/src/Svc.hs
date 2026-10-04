module InvoicesSvc where

import System.Process

handleConvert :: String -> IO ()
handleConvert name = callProcess "convert" ["--", name, "invoices.png"]

endpointPath :: String
endpointPath = "/invoices/v9"
