module Main (main) where

import Control.Monad (forever)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import Network.Socket
import System.FilePath ((</>))
import System.IO

exportRoot :: FilePath
exportRoot = "/srv/exports"

main :: IO ()
main = withSocketsDo $ do
  addr:_ <- getAddrInfo (Just defaultHints { addrFlags = [AI_PASSIVE] }) Nothing (Just "7070")
  sock <- socket (addrFamily addr) Stream defaultProtocol
  bind sock (addrAddress addr)
  listen sock 8
  forever $ do
    (client, _) <- accept sock
    h <- socketToHandle client ReadWriteMode
    hSetBuffering h LineBuffering
    serve h

serve :: Handle -> IO ()
serve h = do
  name <- BC.unpack . BC.strip <$> BS.hGetLine h
  payload <- readExport name
  BS.hPut h payload
  hClose h

readExport :: String -> IO BS.ByteString
readExport name = withFile (exportRoot </> name) ReadMode BS.hGetContents
