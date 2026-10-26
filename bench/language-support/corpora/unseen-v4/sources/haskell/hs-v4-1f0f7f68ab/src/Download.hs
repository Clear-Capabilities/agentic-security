module Download (download) where

import Servant
import qualified Data.ByteString.Lazy as BL
import System.FilePath (combine, splitDirectories, isAbsolute)

type DownloadAPI = "files" :> Capture "fname" FilePath :> Get '[OctetStream] BL.ByteString

download :: FilePath -> Server DownloadAPI
download root fname
  | isAbsolute fname || ".." `elem` splitDirectories fname = throwError err400
  | otherwise = liftIO (BL.readFile (root `combine` fname))
