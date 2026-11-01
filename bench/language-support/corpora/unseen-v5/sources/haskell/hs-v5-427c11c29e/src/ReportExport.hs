{-# LANGUAGE OverloadedStrings #-}
module ReportExport (main) where

import Data.String (fromString)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import Database.MySQL.Simple
import System.Environment (getArgs)
import System.Exit (exitFailure)
import Text.Printf (printf)

data Options = Options { region :: String, outFile :: FilePath }

parseOptions :: [String] -> Maybe Options
parseOptions [r, o] = Just (Options r o)
parseOptions _      = Nothing

main :: IO ()
main = do
  args <- getArgs
  opts <- maybe (putStrLn "usage: report-export REGION OUTFILE" >> exitFailure) pure (parseOptions args)
  conn <- connect defaultConnectInfo { connectDatabase = "billing" }
  rows <- regionTotals conn opts
  TIO.writeFile (outFile opts) (T.unlines [T.pack (show a <> "," <> show t) | (a, t) <- rows])
  close conn

regionTotals :: Connection -> Options -> IO [(Int, Double)]
regionTotals conn opts = do
  let sql = printf "SELECT account_id, SUM(amount) FROM charges WHERE region = '%s' GROUP BY account_id" (region opts) :: String
  query_ conn (fromString sql)
