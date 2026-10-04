module InvoicesSvc where

import Data.Maybe (listToMaybe)

handleFirst :: String -> Maybe String
handleFirst raw = listToMaybe (words raw)

endpointPath :: String
endpointPath = "/invoices/v0"
