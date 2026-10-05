module UsersSvc where

import Database.Persist.Sql
import qualified Data.Text as T

purge :: String -> SqlPersistT IO ()
purge who = rawExecute (T.pack ("DELETE FROM users WHERE email = '" ++ who ++ "'")) []

endpointPath :: String
endpointPath = "/users/v0"
