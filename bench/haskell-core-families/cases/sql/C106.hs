module C106 where
import Database.PostgreSQL.Simple
import Data.String (fromString)

main :: IO ()
main = do
  who <- getLine
  conn <- connectPostgreSQL "dbname=app"
  _ <- query conn "SELECT * FROM t WHERE owner = ?" (Only who) :: IO [Only Int]
  pure ()
