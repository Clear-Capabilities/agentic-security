module OrdersSvc where

import Yesod

getInvoiceR :: InvoiceId -> Handler Value
getInvoiceR invoiceId = do
  _ <- requireAuthId
  invoice <- runDB (get404 invoiceId)
  returnJson invoice

endpointPath :: String
endpointPath = "/orders/v0"
