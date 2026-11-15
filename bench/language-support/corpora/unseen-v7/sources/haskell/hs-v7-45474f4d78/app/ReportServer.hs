module Main (main) where

import Control.Monad (forever)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import Network.Socket
import System.FilePath ((</>), isValid, takeFileName)
import System.IO

reportRoot :: FilePath
reportRoot = "/srv/reports"

main :: IO ()
main = withSocketsDo $ do
  addr:_ <- getAddrInfo (Just defaultHints { addrFlags = [AI_PASSIVE] }) Nothing (Just "7071")
  sock <- socket (addrFamily addr) Stream defaultProtocol
  bind sock (addrAddress addr)
  listen sock 8
  forever $ do
    (client, _) <- accept sock
    h <- socketToHandle client ReadWriteMode
    serve h

plainName :: String -> Bool
plainName name =
  isValid name && takeFileName name == name && name /= "." && name /= ".."

serve :: Handle -> IO ()
serve h = do
  name <- BC.unpack . BC.strip <$> BS.hGetLine h
  if plainName name
    then withFile (reportRoot </> name) ReadMode BS.hGetContents >>= BS.hPut h
    else BC.hPutStrLn h (BC.pack "ERR unknown report")
  hClose h
