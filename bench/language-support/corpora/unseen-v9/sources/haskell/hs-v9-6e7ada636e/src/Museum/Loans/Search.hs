{-# LANGUAGE OverloadedStrings #-}
module Museum.Loans.Search (searchRoutes) where

import Web.Scotty
import Database.PostgreSQL.Simple
import Control.Monad.IO.Class (liftIO)
import Data.String (fromString)
import qualified Data.Text as T
import qualified Data.Text.Lazy as TL

data LoanRow = LoanRow Int T.Text T.Text

instance FromRow LoanRow where
  fromRow = LoanRow <$> field <*> field <*> field

renderLoan :: LoanRow -> TL.Text
renderLoan (LoanRow loanId objectName borrower) =
  TL.fromStrict (T.pack (show loanId) <> "  " <> objectName <> "  lent to " <> borrower)

searchRoutes :: Connection -> ScottyM ()
searchRoutes conn = get "/loans/search" $ do
  borrower <- param "borrower" :: ActionM String
  let sql = "SELECT id, object_name, borrower FROM loans WHERE borrower = '" ++ borrower ++ "' ORDER BY due_at"
  rows <- liftIO (query_ conn (fromString sql)) :: ActionM [LoanRow]
  text (TL.unlines (map renderLoan rows))
