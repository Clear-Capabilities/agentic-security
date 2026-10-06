module OrdersSvc where

import Database.Persist.Sql
import qualified Data.Text as T

purge :: String -> SqlPersistT IO ()
purge who = rawExecute (T.pack ("DELETE FROM orders WHERE ref = '" ++ who ++ "'")) []

endpointPath :: String
endpointPath = "/orders/v0"
