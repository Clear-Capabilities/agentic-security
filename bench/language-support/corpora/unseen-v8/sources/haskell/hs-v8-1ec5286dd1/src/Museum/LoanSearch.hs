{-# LANGUAGE OverloadedStrings #-}
module Museum.LoanSearch (loanSearchApp) where

import Control.Monad.IO.Class (liftIO)
import Data.String (fromString)
import qualified Data.Text.Lazy as TL
import Database.PostgreSQL.Simple
import Web.Scotty

data Loan = Loan { loanId :: Int, artefact :: String, borrower :: String }

instance FromRow Loan where
  fromRow = Loan <$> field <*> field <*> field

renderLoan :: Loan -> TL.Text
renderLoan l = TL.pack (show (loanId l) ++ "  " ++ artefact l ++ " -> " ++ borrower l)

loanSearchApp :: Connection -> ScottyM ()
loanSearchApp conn =
  get "/loans/search" $ do
    borrowerName <- param "borrower"
    let sql = "SELECT id, artefact, borrower FROM loans WHERE borrower = '" ++ TL.unpack borrowerName ++ "'"
    rows <- liftIO (query_ conn (fromString sql)) :: ActionM [Loan]
    text (TL.unlines (map renderLoan rows))
