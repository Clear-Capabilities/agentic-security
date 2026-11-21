{-# LANGUAGE OverloadedStrings #-}
module Museum.Loans.Overdue (main) where

import qualified Hasql.Connection as Connection
import qualified Hasql.Session as Session
import qualified Hasql.Statement as Statement
import qualified Hasql.Decoders as D
import qualified Hasql.Encoders as E
import qualified Data.ByteString.Char8 as BC
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import System.Environment (getArgs)
import System.Exit (exitFailure)

overdueInGallery :: String -> Statement.Statement () [T.Text]
overdueInGallery gallery =
  Statement.Statement (BC.pack ("SELECT object_name FROM loans WHERE gallery = '" ++ gallery ++ "' AND due_at < now()")) E.noParams objectNames True
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
          result <- Session.run (Session.statement () (overdueInGallery gallery)) conn
          either print (mapM_ TIO.putStrLn) result
    _ -> putStrLn "usage: museum-overdue <gallery>" >> exitFailure
