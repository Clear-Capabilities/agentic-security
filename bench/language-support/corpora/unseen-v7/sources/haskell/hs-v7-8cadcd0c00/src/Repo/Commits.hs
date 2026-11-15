{-# LANGUAGE OverloadedStrings #-}
module Repo.Commits (commitRoutes) where

import Control.Monad.IO.Class (liftIO)
import Data.Char (isAlphaNum)
import Data.Text (Text)
import qualified Data.Text as T
import Network.HTTP.Types.Status (status400)
import Shelly (run, shelly, silently)
import Web.Spock

commitRoutes :: SpockM () () () ()
commitRoutes =
  get ("repos" <//> "billing" <//> "commits") $ do
    branch <- param' "branch"
    if validRef branch
      then do
        out <- liftIO (recentCommits branch)
        text out
      else do
        setStatus status400
        text "branch name not accepted"

validRef :: Text -> Bool
validRef ref =
  not (T.null ref)
    && not (T.isPrefixOf "-" ref)
    && T.all (\c -> isAlphaNum c || c `elem` ("/_.-" :: String)) ref

recentCommits :: Text -> IO Text
recentCommits branch =
  shelly . silently $ run "git" ["-C", "/srv/repos/billing", "log", "--oneline", "-n", "20", branch]
