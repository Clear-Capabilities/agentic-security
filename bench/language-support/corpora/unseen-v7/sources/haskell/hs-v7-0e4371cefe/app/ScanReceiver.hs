module Main (main) where

import Control.Monad (forever)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import Network.Socket
import System.IO
import Text.Read (readMaybe)

import Scans (storeScan)

main :: IO ()
main = withSocketsDo $ do
  addr:_ <- getAddrInfo (Just defaultHints { addrFlags = [AI_PASSIVE] }) Nothing (Just "6000")
  sock <- socket (addrFamily addr) Stream defaultProtocol
  bind sock (addrAddress addr)
  listen sock 16
  forever $ do
    (client, _) <- accept sock
    h <- socketToHandle client ReadWriteMode
    hSetBinaryMode h True
    serve h
    hClose h

-- protocol: one ASCII line with the byte count, then that many bytes of scan data
serve :: Handle -> IO ()
serve h = do
  header <- BC.unpack . BC.strip <$> BS.hGetLine h
  case readMaybe header of
    Nothing -> BC.hPutStrLn h (BC.pack "ERR expected a length")
    Just n -> do
      payload <- BS.hGet h n
      storeScan payload
      BC.hPutStrLn h (BC.pack "OK")
