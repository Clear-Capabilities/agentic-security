module C104 where
import Database.PostgreSQL.Simple
import Data.String (fromString)

run :: Connection -> IO ()
run conn = do
  n <- getLine
  _ <- execute conn "DELETE FROM t WHERE n = ?" (Only n)
  pure ()
