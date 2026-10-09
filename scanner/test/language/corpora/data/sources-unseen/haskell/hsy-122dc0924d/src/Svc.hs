module UsersSvc where

import Yesod

getInvoiceR :: InvoiceId -> Handler Value
getInvoiceR invoiceId = do
  uid <- requireAuthId
  found <- runDB (selectFirst [InvoiceId ==. invoiceId, InvoiceOwner ==. uid] [])
  maybe notFound returnJson found

endpointPath :: String
endpointPath = "/users/v0"
