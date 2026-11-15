module Warehouse.RobotLink (serveRobot) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import Network.Socket (Socket, socketToHandle)
import System.IO

-- Each frame is a decimal length, a newline, then that many bytes of status.
serveRobot :: Socket -> (BS.ByteString -> IO ()) -> IO ()
serveRobot sock handleFrame = do
  h <- socketToHandle sock ReadMode
  hSetBuffering h (BlockBuffering Nothing)
  loop h
  where
    loop h = do
      eof <- hIsEOF h
      if eof
        then hClose h
        else do
          header <- B8.hGetLine h
          case B8.readInt header of
            Just (len, _) -> do
              frame <- BS.hGet h len
              handleFrame frame
              loop h
            Nothing -> hClose h
