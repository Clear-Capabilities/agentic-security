module InvoicesSvc where

import System.IO
import System.FilePath (takeFileName)

handleDownload :: String -> IO String
handleDownload name = readFile ("/srv/invoices/" ++ takeFileName name)

endpointPath :: String
endpointPath = "/invoices/v0"
