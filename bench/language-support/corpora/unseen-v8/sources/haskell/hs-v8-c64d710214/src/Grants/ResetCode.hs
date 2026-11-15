{-# LANGUAGE OverloadedStrings #-}
module Grants.ResetCode (ResetCode (..), issueResetCode) where

import Control.Monad (replicateM)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time (UTCTime, addUTCTime, getCurrentTime)
import System.Random (randomRIO)

data ResetCode = ResetCode { code :: Text, expiresAt :: UTCTime, applicant :: Text }

alphabet :: String
alphabet = ['A' .. 'Z'] ++ ['2' .. '9']

issueResetCode :: Text -> IO ResetCode
issueResetCode applicantEmail = do
  picks <- replicateM 8 (randomRIO (0, length alphabet - 1))
  now <- getCurrentTime
  pure ResetCode
    { code = T.pack (map (alphabet !!) picks)
    , expiresAt = addUTCTime 900 now
    , applicant = applicantEmail
    }
