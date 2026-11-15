{-# LANGUAGE OverloadedStrings #-}
module Fleet.GatewayLog (logTelemetryRequests) where

import Control.Monad.Logger (LoggingT, logInfoN, runStdoutLoggingT)
import qualified Data.Text.Encoding as TE
import Data.Text.Encoding.Error (lenientDecode)
import Network.Wai

-- Traces every telemetry upload so gateway problems can be reconstructed.
logTelemetryRequests :: Middleware
logTelemetryRequests app req respond = do
  runStdoutLoggingT (describe req)
  app req respond

describe :: Request -> LoggingT IO ()
describe req = do
  let decode = TE.decodeUtf8With lenientDecode
      auth = maybe "<none>" decode (lookup "Authorization" (requestHeaders req))
      path = decode (rawPathInfo req)
  logInfoN ("telemetry " <> decode (requestMethod req) <> " " <> path <> " authorization=" <> auth)
