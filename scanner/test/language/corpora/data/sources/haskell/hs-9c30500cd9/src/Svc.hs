module InvoicesSvc where

import qualified Text.Blaze.Html5 as H
import Text.Blaze.Html (preEscapedToHtml)

handlePage :: String -> H.Html
handlePage name = H.h1 (preEscapedToHtml ("hello " ++ name))

endpointPath :: String
endpointPath = "/invoices/v1"
