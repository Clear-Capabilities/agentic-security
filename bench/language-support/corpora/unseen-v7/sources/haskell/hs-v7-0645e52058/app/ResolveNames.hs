{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Control.Monad (forM_)
import Data.Char (isAlphaNum)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import Turtle (ExitCode(..), empty, proc)

main :: IO ()
main = do
  contents <- TIO.getContents
  forM_ (map T.strip (T.lines contents)) $ \host -> do
    result <- resolve host
    case result of
      Nothing -> TIO.putStrLn ("skipping malformed name " <> host)
      Just ExitSuccess -> TIO.putStrLn ("resolved " <> host)
      Just (ExitFailure n) -> TIO.putStrLn ("lookup of " <> host <> " failed with " <> T.pack (show n))

hostChar :: Char -> Bool
hostChar c = isAlphaNum c || c == '.' || c == '-'

resolve :: T.Text -> IO (Maybe ExitCode)
resolve host
  | T.null host || T.length host > 253 || not (T.all hostChar host) = pure Nothing
  | T.isPrefixOf "-" host = pure Nothing
  | otherwise = Just <$> proc "dig" ["+short", host] empty
