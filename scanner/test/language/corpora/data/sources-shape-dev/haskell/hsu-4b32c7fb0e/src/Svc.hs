module UsersSvc where

import Database.SQLite.Simple
import Data.String (fromString)

countIn :: Connection -> String -> IO [Only Int]
countIn conn table = query_ conn q
  where
    q = fromString ("SELECT count(*) FROM " ++ table)

endpointPath :: String
endpointPath = "/users/u0"
