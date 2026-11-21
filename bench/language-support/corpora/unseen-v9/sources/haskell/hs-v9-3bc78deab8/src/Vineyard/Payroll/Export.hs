{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings #-}
module Vineyard.Payroll.Export (ExportAPI, exportServer) where

import Servant
import Control.Monad.Logger (runStdoutLoggingT, logInfoN)
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text as T

type ExportAPI =
  "payroll" :> "export"
    :> Header' '[Required] "Authorization" T.Text
    :> QueryParam' '[Required] "period" T.Text
    :> Get '[JSON] [T.Text]

exportServer :: (T.Text -> IO Bool) -> (T.Text -> IO [T.Text]) -> Server ExportAPI
exportServer tokenAllowed loadPeriod authorization period = do
  liftIO (runStdoutLoggingT (logInfoN ("payroll export period=" <> period <> " authorization=" <> authorization)))
  allowed <- liftIO (tokenAllowed authorization)
  if allowed then liftIO (loadPeriod period) else throwError err401
