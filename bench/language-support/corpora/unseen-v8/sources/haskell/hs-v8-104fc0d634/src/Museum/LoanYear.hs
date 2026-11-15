{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Museum.LoanYear (LoansByYearAPI, loansByYear) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import qualified Data.Text as T
import Servant
import Text.Read (readMaybe)

type LoansByYearAPI = "loans" :> "by-year" :> QueryParam' '[Required] "year" Text :> Get '[JSON] [Text]

loansByYear :: (Int -> IO [Text]) -> Server LoansByYearAPI
loansByYear fetch yearText =
  case readMaybe (T.unpack yearText) of
    Just year | year >= 1850, year <= 2100 -> liftIO (fetch year)
    _ -> throwError err400 { errBody = "year must be a four digit number" }
