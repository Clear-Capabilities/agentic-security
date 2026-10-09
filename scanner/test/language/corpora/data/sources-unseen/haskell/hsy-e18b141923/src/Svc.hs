module OrdersSvc where

import Database.PostgreSQL.Simple
import Data.String (fromString)

tableName :: String
tableName = "orders"

countFor :: Connection -> String -> IO [Only Int]
countFor conn who = query conn (fromString ("SELECT count(*) FROM " ++ tableName ++ " WHERE ref = ?")) (Only who)

endpointPath :: String
endpointPath = "/orders/v0"
