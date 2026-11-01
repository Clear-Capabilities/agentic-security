module ReportExport (main) where

import Data.List (intercalate)
import Data.String (fromString)
import Database.MySQL.Simple
import System.Environment (getArgs)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)
import Text.Printf (printf)

type DealRow = (Int, String, Double)

main :: IO ()
main = do
  args <- getArgs
  case args of
    [region] -> exportRegion region
    _ -> hPutStrLn stderr "usage: report-export <region>" >> exitFailure

exportRegion :: String -> IO ()
exportRegion region = do
  conn <- connect defaultConnectInfo { connectDatabase = "sales" }
  let statement = printf "SELECT id, account, amount FROM deals WHERE region = '%s' ORDER BY amount DESC" region
  rows <- query_ conn (fromString statement) :: IO [DealRow]
  putStr (unlines (map renderRow rows))
  close conn

renderRow :: DealRow -> String
renderRow (i, account, amount) = intercalate "," [show i, account, show amount]
