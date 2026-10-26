{-# LANGUAGE ScopedTypeVariables #-}
module Archive (backup) where

import System.Process
import System.Exit
import Network.Wai
import qualified Data.ByteString.Char8 as B

backup :: Request -> IO ExitCode
backup req = do
  let dir = maybe "." B.unpack (join' (lookup (B.pack "dir") (queryString req)))
  (_, _, _, ph) <- createProcess (shell ("tar czf /tmp/backup.tgz " ++ dir))
  waitForProcess ph
  where
    join' (Just (Just x)) = Just x
    join' _               = Nothing
