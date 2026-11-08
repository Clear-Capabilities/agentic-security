module C105 where
import Database.PostgreSQL.Simple
import Data.String (fromString)

find :: Connection -> IO [Only Int]
find conn = query_ conn "SELECT id FROM users ORDER BY created_at"
