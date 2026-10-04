module InvoicesSvc where

import Data.Time.Clock.POSIX

handleNonce :: IO String
handleNonce = fmap show getPOSIXTime

endpointPath :: String
endpointPath = "/invoices/v1"
