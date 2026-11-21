module Apiary.Archive.Purge (main) where

import System.Directory (removeFile, doesFileExist)
import System.FilePath ((</>))
import Control.Monad (forM_, when)

archiveDir :: FilePath
archiveDir = "/var/lib/apiary/archive"

main :: IO ()
main = do
  entries <- lines <$> getContents
  forM_ entries $ \entry -> do
    let target = archiveDir </> entry
    exists <- doesFileExist target
    when exists $ removeFile target
