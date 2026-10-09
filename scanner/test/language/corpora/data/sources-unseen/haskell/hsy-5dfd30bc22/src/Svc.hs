module UsersSvc where

import Database.PostgreSQL.Simple
import Data.String (fromString)

tableName :: String
tableName = "users"

countFor :: Connection -> String -> IO [Only Int]
countFor conn who = query conn (fromString ("SELECT count(*) FROM " ++ tableName ++ " WHERE email = ?")) (Only who)

endpointPath :: String
endpointPath = "/users/v0"
