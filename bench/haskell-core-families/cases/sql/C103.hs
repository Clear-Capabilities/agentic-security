module C103 where
import Database.PostgreSQL.Simple
import Data.String (fromString)
import System.Environment (getArgs)

main :: IO ()
main = do
  (who:_) <- getArgs
  conn <- connectPostgreSQL "dbname=app"
  _ <- query_ conn (fromString ("SELECT * FROM t WHERE owner = '" ++ who ++ "'")) :: IO [Only Int]
  pure ()
