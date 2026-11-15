module Radio.FeedSocket (readFrames) where

import Control.Exception (throwIO)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import System.IO

maxFrameBytes :: Int
maxFrameBytes = 65536

-- Schedule updates arrive as "<length>\n<payload>" frames from the automation desk.
readFrames :: Handle -> (BS.ByteString -> IO ()) -> IO ()
readFrames h onFrame = go
  where
    go = do
      done <- hIsEOF h
      if done
        then pure ()
        else do
          header <- B8.hGetLine h
          len <- case B8.readInt header of
            Just (n, rest) | B8.null rest, n >= 0, n <= maxFrameBytes -> pure n
            _ -> throwIO (userError "bad frame header")
          frame <- BS.hGet h len
          onFrame frame
          go
