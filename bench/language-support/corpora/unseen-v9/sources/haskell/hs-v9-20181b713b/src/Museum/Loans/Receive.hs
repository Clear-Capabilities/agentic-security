{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings #-}
module Museum.Loans.Receive (ReceiveAPI, receiveServer) where

import Servant
import Database.SQLite.Simple
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text as T

type ReceiveAPI = "loans" :> Capture "reference" T.Text :> "return" :> Post '[JSON] NoContent

receiveServer :: Connection -> Server ReceiveAPI
receiveServer conn reference = do
  liftIO (execute conn "UPDATE loans SET returned_at = CURRENT_TIMESTAMP WHERE reference = ?" (Only reference))
  pure NoContent
