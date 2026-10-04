module InvoicesSvc where

import System.Process
class Sink a where
  emitInvoices :: a -> IO ()

handleConvert :: String -> IO ()
handleConvert name = callCommand ("convert " ++ name ++ " invoices.png")

endpointPath :: String
endpointPath = "/invoices/v0"
