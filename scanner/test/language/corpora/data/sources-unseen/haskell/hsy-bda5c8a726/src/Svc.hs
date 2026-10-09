module UsersSvc where

import Yesod
import Database.Persist.Sql (rawExecute)

postPurgeR :: Handler Text
postPurgeR = do
  runDB (rawExecute "DELETE FROM users" [])
  return "purged"

endpointPath :: String
endpointPath = "/users/v0"
