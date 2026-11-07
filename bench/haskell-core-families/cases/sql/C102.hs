module C102 where
import Database.PostgreSQL.Simple
import Data.String (fromString)

find :: Connection -> IO [Only Int]
find conn = do
  col <- getLine
  query_ conn (fromString ("SELECT id FROM users ORDER BY " ++ col))
