{-# LANGUAGE OverloadedStrings #-}
module Labels.Ingest (ingestApp) where

import qualified Data.ByteString.Lazy.Char8 as BLC
import Network.HTTP.Types
import Network.Wai

import Labels.Queue (enqueueLabelBatch)

ingestApp :: Application
ingestApp req respond
  | requestMethod req == methodPost && pathInfo req == ["labels", "batch"] = do
      body <- strictRequestBody req
      count <- enqueueLabelBatch body
      respond (responseLBS status202 [("Content-Type", "text/plain")] (BLC.pack (show count)))
  | otherwise =
      respond (responseLBS status404 [] "")
