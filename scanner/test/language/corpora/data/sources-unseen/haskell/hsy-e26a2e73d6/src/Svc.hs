module UsersSvc where

import Yesod
import Control.Monad (when)

getInvoiceR :: InvoiceId -> Handler Value
getInvoiceR invoiceId = do
  uid <- requireAuthId
  invoice <- runDB (get404 invoiceId)
  when (invoiceOwner invoice /= uid) notFound
  returnJson invoice

endpointPath :: String
endpointPath = "/users/v0"
