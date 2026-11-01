{-# LANGUAGE OverloadedStrings #-}
module ImportRows (main) where

import qualified Data.ByteString.Lazy as BL
import Data.Csv (HasHeader(..), decode)
import Data.Text (Text)
import qualified Data.Vector as V
import System.Environment (getArgs)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)
import qualified Inventory

main :: IO ()
main = do
  args <- getArgs
  case args of
    [path] -> importFile path
    _ -> hPutStrLn stderr "usage: import-rows <file.csv>" >> exitFailure

importFile :: FilePath -> IO ()
importFile path = do
  contents <- BL.readFile path
  case decode HasHeader contents :: Either String (V.Vector (Text, Int)) of
    Left reason -> hPutStrLn stderr ("could not parse " ++ path ++ ": " ++ reason) >> exitFailure
    Right rows -> do
      mapM_ (uncurry Inventory.adjust) (V.toList rows)
      putStrLn ("imported " ++ show (V.length rows) ++ " rows")
