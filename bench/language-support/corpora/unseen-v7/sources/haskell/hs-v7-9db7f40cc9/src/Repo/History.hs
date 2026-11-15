module Repo.History (historyHandler) where

import Control.Monad.IO.Class (liftIO)
import Happstack.Server
import System.Process (readCreateProcess, shell)

historyHandler :: ServerPart Response
historyHandler = dir "history" $ do
  method GET
  branch <- look "branch"
  out <- liftIO (recentCommits branch)
  ok (toResponse out)

recentCommits :: String -> IO String
recentCommits branch =
  readCreateProcess (shell ("git -C /srv/repos/billing log --oneline -n 20 " ++ branch)) ""
