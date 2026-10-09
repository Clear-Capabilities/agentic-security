module OrdersSvc where

import Yesod
import Database.Persist.Sql (rawExecute)

postPurgeR :: Handler Text
postPurgeR = do
  runDB (rawExecute "DELETE FROM orders" [])
  return "purged"

endpointPath :: String
endpointPath = "/orders/v0"
