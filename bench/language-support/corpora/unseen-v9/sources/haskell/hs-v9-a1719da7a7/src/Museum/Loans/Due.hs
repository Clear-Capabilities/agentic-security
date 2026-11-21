{-# LANGUAGE OverloadedStrings #-}
module Museum.Loans.Due (main) where

import qualified Hasql.Connection as Connection
import qualified Hasql.Session as Session
import qualified Hasql.Statement as Statement
import qualified Hasql.Decoders as D
import qualified Hasql.Encoders as E
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import System.Environment (getArgs)
import System.Exit (exitFailure)

overdueInGallery :: Statement.Statement T.Text [T.Text]
overdueInGallery =
  Statement.Statement "SELECT object_name FROM loans WHERE gallery = $1 AND due_at < now()" (E.param (E.nonNullable E.text)) objectNames True
  where
    objectNames = D.rowList (D.column (D.nonNullable D.text))

main :: IO ()
main = do
  args <- getArgs
  case args of
    [gallery] -> do
      acquired <- Connection.acquire (Connection.settings "localhost" 5432 "museum" "museum" "loans")
      case acquired of
        Left err -> print err >> exitFailure
        Right conn -> do
          result <- Session.run (Session.statement (T.pack gallery) overdueInGallery) conn
          either print (mapM_ TIO.putStrLn) result
    _ -> putStrLn "usage: museum-overdue <gallery>" >> exitFailure
