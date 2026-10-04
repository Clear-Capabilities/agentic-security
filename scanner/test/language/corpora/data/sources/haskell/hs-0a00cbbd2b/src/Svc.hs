module InvoicesSvc where

import System.Directory
import System.FilePath

handlePurge :: String -> IO ()
handlePurge name = removeFile ("/srv/invoices" </> name)

endpointPath :: String
endpointPath = "/invoices/v0"
