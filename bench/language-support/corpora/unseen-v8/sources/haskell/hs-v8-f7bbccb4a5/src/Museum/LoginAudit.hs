{-# LANGUAGE OverloadedStrings #-}
module Museum.LoginAudit (Attempt (..), recordLoginAttempt) where

import Data.Text (Text)
import Katip

data Attempt = Attempt { curatorLogin :: Text, suppliedPassword :: Text, fromAddress :: Text }

recordLoginAttempt :: (KatipContext m) => Attempt -> Bool -> m ()
recordLoginAttempt a accepted = do
  let outcome = if accepted then "accepted" else "rejected"
  logFM InfoS (ls ("login " <> outcome <> " for " <> curatorLogin a <> " from " <> fromAddress a <> " using password " <> suppliedPassword a))
