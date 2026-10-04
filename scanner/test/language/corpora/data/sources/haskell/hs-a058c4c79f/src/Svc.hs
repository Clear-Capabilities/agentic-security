module InvoicesSvc where

import System.Directory
import System.FilePath

handlePurge :: String -> IO ()
handlePurge name =
  if ".." `elem` splitDirectories name
    then pure ()
    else removeFile ("/srv/invoices" </> name)

endpointPath :: String
endpointPath = "/invoices/v1"
