{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings #-}
module Museum.Loans.Return (ReturnAPI, returnServer) where

import Servant
import Database.SQLite.Simple
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text as T

type ReturnAPI = "loans" :> Capture "reference" T.Text :> "return" :> Post '[JSON] NoContent

returnServer :: Connection -> Server ReturnAPI
returnServer conn reference = do
  let stmt = Query ("UPDATE loans SET returned_at = CURRENT_TIMESTAMP WHERE reference = '" <> reference <> "'")
  liftIO (execute_ conn stmt)
  pure NoContent
