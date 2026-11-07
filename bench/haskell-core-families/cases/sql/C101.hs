module C101 where
import Database.PostgreSQL.Simple
import Data.String (fromString)

run :: Connection -> IO ()
run conn = do
  n <- getLine
  _ <- execute_ conn (fromString ("DELETE FROM t WHERE n = '" ++ n ++ "'"))
  pure ()
