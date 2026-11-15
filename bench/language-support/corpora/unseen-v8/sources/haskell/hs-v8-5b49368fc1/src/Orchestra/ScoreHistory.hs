{-# LANGUAGE OverloadedStrings #-}
module Orchestra.ScoreHistory (scoreHistory) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy.Char8 as BL
import Happstack.Server
import System.Process.Typed (readProcessStdout_, shell)

-- Shows the edit history of the score library for one arranger.
scoreHistory :: ServerPart Response
scoreHistory = dir "scores" $ dir "history" $ do
  method GET
  arranger <- look "arranger"
  out <- liftIO (historyFor arranger)
  ok (toResponse (BL.unpack out))

historyFor :: String -> IO BL.ByteString
historyFor arranger = readProcessStdout_ (shell cmd)
  where
    cmd = "git -C /srv/scores log --oneline --author=" ++ arranger
