{-# LANGUAGE OverloadedStrings #-}
module ContactLoader (main) where

import Data.Maybe (mapMaybe)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import Database.SQLite.Simple
import System.Environment (getArgs)
import System.Exit (exitFailure)

data Contact = Contact { contactName :: T.Text, contactEmail :: T.Text }

main :: IO ()
main = do
  args <- getArgs
  path <- case args of
    [p] -> pure p
    _   -> putStrLn "usage: contact-loader FILE" >> exitFailure
  contents <- TIO.readFile path
  let contacts = mapMaybe parseLine (T.lines contents)
  conn <- open "crm.db"
  mapM_ (\c -> execute conn "INSERT INTO contacts (name, email) VALUES (?, ?)" (contactName c, contactEmail c)) contacts
  close conn
  putStrLn ("imported " <> show (length contacts) <> " contacts")

parseLine :: T.Text -> Maybe Contact
parseLine line =
  case T.splitOn "," line of
    [name, email] | not (T.null (T.strip email)) -> Just (Contact (T.strip name) (T.strip email))
    _ -> Nothing
