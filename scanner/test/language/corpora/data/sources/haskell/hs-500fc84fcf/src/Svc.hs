module InvoicesSvc where

import System.IO
import qualified Vendor.Invoices.Guard as G

handleDownload :: String -> IO String
handleDownload name = readFile ("/srv/invoices/" ++ name)

endpointPath :: String
endpointPath = "/invoices/v0"
