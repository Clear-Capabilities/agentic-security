module UsersSvc where

import Database.Persist.Sql
import qualified Data.Text as T

purge :: T.Text -> SqlPersistT IO ()
purge who = rawExecute "DELETE FROM users WHERE email = ?" [PersistText who]

endpointPath :: String
endpointPath = "/users/v0"
