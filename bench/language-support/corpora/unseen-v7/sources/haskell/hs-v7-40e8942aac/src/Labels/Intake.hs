{-# LANGUAGE OverloadedStrings #-}
module Labels.Intake (intakeApp) where

import qualified Data.ByteString.Lazy.Char8 as BLC
import Data.Word (Word64)
import Network.HTTP.Types
import Network.Wai

import Labels.Queue (enqueueLabelBatch)

maxBatchBytes :: Word64
maxBatchBytes = 2 * 1024 * 1024

intakeApp :: Application
intakeApp req respond
  | requestMethod req == methodPost && pathInfo req == ["labels", "batch"] =
      case requestBodyLength req of
        KnownLength n | n <= maxBatchBytes -> do
          body <- strictRequestBody req
          count <- enqueueLabelBatch body
          respond (responseLBS status202 [("Content-Type", "text/plain")] (BLC.pack (show count)))
        _ ->
          respond (responseLBS status413 [] "batch too large or of unknown length")
  | otherwise =
      respond (responseLBS status404 [] "")
