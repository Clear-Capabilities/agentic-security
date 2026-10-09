module OrdersSvc where

import Database.Persist.Sql
import qualified Data.Text as T

purge :: T.Text -> SqlPersistT IO ()
purge who = rawExecute "DELETE FROM orders WHERE ref = ?" [PersistText who]

endpointPath :: String
endpointPath = "/orders/v0"
