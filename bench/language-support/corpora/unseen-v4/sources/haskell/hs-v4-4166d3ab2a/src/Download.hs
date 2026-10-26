module Download (download) where

import Servant
import qualified Data.ByteString.Lazy as BL
import System.FilePath (combine)

type DownloadAPI = "files" :> Capture "fname" FilePath :> Get '[OctetStream] BL.ByteString

download :: FilePath -> Server DownloadAPI
download root fname = liftIO (BL.readFile (root `combine` fname))
