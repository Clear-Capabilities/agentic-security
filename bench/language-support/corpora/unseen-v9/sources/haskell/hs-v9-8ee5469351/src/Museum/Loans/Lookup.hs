{-# LANGUAGE OverloadedStrings #-}
module Museum.Loans.Lookup (lookupRoutes) where

import Web.Scotty
import Database.PostgreSQL.Simple
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text as T
import qualified Data.Text.Lazy as TL

data LoanRow = LoanRow Int T.Text T.Text

instance FromRow LoanRow where
  fromRow = LoanRow <$> field <*> field <*> field

renderLoan :: LoanRow -> TL.Text
renderLoan (LoanRow loanId objectName borrower) =
  TL.fromStrict (T.pack (show loanId) <> "  " <> objectName <> "  lent to " <> borrower)

lookupRoutes :: Connection -> ScottyM ()
lookupRoutes conn = get "/loans/search" $ do
  borrower <- param "borrower" :: ActionM T.Text
  rows <- liftIO (query conn "SELECT id, object_name, borrower FROM loans WHERE borrower = ? ORDER BY due_at" (Only borrower)) :: ActionM [LoanRow]
  text (TL.unlines (map renderLoan rows))
