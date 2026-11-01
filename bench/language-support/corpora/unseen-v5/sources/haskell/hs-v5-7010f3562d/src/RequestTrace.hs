{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings #-}
module RequestTrace (TraceApi, traceServer) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import qualified Data.Text as T
import Servant
import System.Log.FastLogger (LoggerSet, pushLogStrLn, toLogStr)

type TraceApi = "account" :> "balance" :> Header' '[Required] "Authorization" Text :> Get '[JSON] Double

traceServer :: LoggerSet -> Server TraceApi
traceServer logger authorization = do
  liftIO (logRequest logger "GET /account/balance" authorization)
  pure 1280.55

logRequest :: LoggerSet -> Text -> Text -> IO ()
logRequest logger route authorization =
  pushLogStrLn logger (toLogStr (T.concat ["route=", route, " authorization=", authorization]))
