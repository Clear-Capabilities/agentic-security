{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings #-}
module Vineyard.Payroll.Extract (ExtractAPI, extractServer) where

import Servant
import Control.Monad.Logger (runStdoutLoggingT, logInfoN)
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text as T

type ExtractAPI =
  "payroll" :> "export"
    :> Header' '[Required] "Authorization" T.Text
    :> QueryParam' '[Required] "period" T.Text
    :> Get '[JSON] [T.Text]

extractServer :: (T.Text -> IO Bool) -> (T.Text -> IO [T.Text]) -> Server ExtractAPI
extractServer tokenAllowed loadPeriod authorization period = do
  liftIO (runStdoutLoggingT (logInfoN ("payroll export period=" <> period <> " token_prefix=" <> T.take 4 authorization <> "...")))
  allowed <- liftIO (tokenAllowed authorization)
  if allowed then liftIO (loadPeriod period) else throwError err401
