{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings #-}
module RequestLog (LogApi, logServer) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import qualified Data.Text as T
import Servant
import System.Log.FastLogger (LoggerSet, pushLogStrLn, toLogStr)

type LogApi = "account" :> "balance" :> Header' '[Required] "Authorization" Text :> Get '[JSON] Double

logServer :: LoggerSet -> Server LogApi
logServer logger authorization = do
  liftIO (logRequest logger "GET /account/balance" authorization)
  pure 1280.55

redact :: Text -> Text
redact t = T.replicate (max 0 (T.length t - 4)) "*" <> T.takeEnd 4 t

logRequest :: LoggerSet -> Text -> Text -> IO ()
logRequest logger route authorization =
  pushLogStrLn logger (toLogStr (T.concat ["route=", route, " authorization=", redact authorization]))
