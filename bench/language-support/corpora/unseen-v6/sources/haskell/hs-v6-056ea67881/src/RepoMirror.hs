{-# LANGUAGE OverloadedStrings #-}
module RepoMirror (main) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Char8 as B
import Snap.Core
import Snap.Http.Server (quickHttpServe)
import System.Process.Typed (runProcess_, setWorkingDir, shell)

main :: IO ()
main = quickHttpServe $ route [("mirror", method POST mirrorHandler)]

mirrorHandler :: Snap ()
mirrorHandler = do
  req <- getRequest
  case getHeader "X-Repo-Url" req of
    Nothing -> do
      modifyResponse (setResponseStatus 400 "Bad Request")
      writeBS "repo url header required"
    Just url -> do
      liftIO (cloneInto "/var/mirrors" (B.unpack url))
      writeBS "mirror started"

cloneInto :: FilePath -> String -> IO ()
cloneInto base url = runProcess_ (setWorkingDir base (shell ("git clone --mirror " ++ url)))
