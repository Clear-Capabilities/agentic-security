module Fleet.CompressedUpload (drainSpool) where

import qualified Codec.Compression.GZip as GZip
import qualified Data.ByteString.Lazy as BL
import System.Directory (listDirectory, removeFile)
import System.FilePath (takeExtension, (</>))

-- Trackers upload gzip batches to the spool; this worker unpacks them.
drainSpool :: FilePath -> (BL.ByteString -> IO ()) -> IO ()
drainSpool spool ingest = do
  names <- filter ((== ".gz") . takeExtension) <$> listDirectory spool
  mapM_ unpackOne names
  where
    unpackOne name = do
      compressed <- BL.readFile (spool </> name)
      ingest (GZip.decompress compressed)
      removeFile (spool </> name)
