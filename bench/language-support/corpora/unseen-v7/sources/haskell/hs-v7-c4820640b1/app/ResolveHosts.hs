{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Control.Monad (forM_)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import Turtle (ExitCode(..), empty, shell)

main :: IO ()
main = do
  contents <- TIO.getContents
  forM_ (filter (not . T.null) (map T.strip (T.lines contents))) $ \host -> do
    code <- resolve host
    case code of
      ExitSuccess   -> TIO.putStrLn ("resolved " <> host)
      ExitFailure n -> TIO.putStrLn ("lookup of " <> host <> " failed with " <> T.pack (show n))

resolve :: T.Text -> IO ExitCode
resolve host = shell ("dig +short " <> host) empty
