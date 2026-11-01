{-# LANGUAGE OverloadedStrings #-}
module ContactImport (main) where

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
    _   -> putStrLn "usage: contact-import FILE" >> exitFailure
  contents <- TIO.readFile path
  let contacts = map parseLine (filter (not . T.null) (T.lines contents))
  conn <- open "crm.db"
  mapM_ (\c -> execute conn "INSERT INTO contacts (name, email) VALUES (?, ?)" (contactName c, contactEmail c)) contacts
  close conn
  putStrLn ("imported " <> show (length contacts) <> " contacts")

parseLine :: T.Text -> Contact
parseLine line =
  let [name, email] = T.splitOn "," line
  in Contact (T.strip name) (T.strip email)
