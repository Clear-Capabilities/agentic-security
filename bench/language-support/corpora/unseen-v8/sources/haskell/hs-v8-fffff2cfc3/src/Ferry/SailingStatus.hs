{-# LANGUAGE OverloadedStrings #-}
module Ferry.SailingStatus (sailingStatus) where

import Data.Aeson (Value)
import Data.Char (isDigit)
import Data.Text (Text)
import qualified Data.Text as T
import Network.HTTP.Req

-- Asks the harbour authority whether a sailing is still scheduled.
sailingStatus :: Text -> IO (Either Text Value)
sailingStatus sailingNo
  | T.null sailingNo || not (T.all isDigit sailingNo) = pure (Left "sailing numbers are numeric")
  | otherwise = runReq defaultHttpConfig $ do
      r <- req GET (https "harbour.example" /: "v2" /: "sailings" /: sailingNo) NoReqBody jsonResponse mempty
      pure (Right (responseBody r))
