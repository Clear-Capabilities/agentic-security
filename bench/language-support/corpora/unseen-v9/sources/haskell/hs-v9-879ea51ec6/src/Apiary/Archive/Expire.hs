module Apiary.Archive.Expire (main) where

import System.Directory (removeFile, doesFileExist)
import System.FilePath ((</>))
import System.IO (hPutStrLn, stderr)
import Control.Monad (forM_, when)
import Text.Read (readMaybe)

archiveDir :: FilePath
archiveDir = "/var/lib/apiary/archive"

main :: IO ()
main = do
  entries <- lines <$> getContents
  forM_ entries $ \entry ->
    case readMaybe entry :: Maybe Int of
      Nothing -> hPutStrLn stderr ("skipping entry that is not a hive number: " ++ entry)
      Just hiveNumber -> do
        let target = archiveDir </> ("hive-" ++ show hiveNumber ++ ".csv")
        exists <- doesFileExist target
        when exists $ removeFile target
