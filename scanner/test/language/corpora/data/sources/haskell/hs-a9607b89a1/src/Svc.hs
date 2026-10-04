module InvoicesSvc where

import System.Process

handleUnpack :: String -> IO ()
handleUnpack name = callProcess "sh" ["-c", "tar xf " ++ name ++ " -C /srv/invoices"]

endpointPath :: String
endpointPath = "/invoices/v1"
