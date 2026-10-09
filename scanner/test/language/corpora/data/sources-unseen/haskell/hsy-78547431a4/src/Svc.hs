module OrdersSvc where

import Database.Persist.Sql
import qualified Data.Text as T

findByName :: T.Text -> SqlPersistT IO [Single T.Text]
findByName who = rawSql (T.concat ["SELECT ref FROM orders WHERE ref = '", who, "'"]) []

endpointPath :: String
endpointPath = "/orders/v0"
