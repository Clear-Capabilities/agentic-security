module UsersSvc where

import Database.Persist.Sql
import qualified Data.Text as T

findByName :: T.Text -> SqlPersistT IO [Single T.Text]
findByName who = rawSql "SELECT email FROM users WHERE email = ?" [toPersistValue who]

endpointPath :: String
endpointPath = "/users/v0"
