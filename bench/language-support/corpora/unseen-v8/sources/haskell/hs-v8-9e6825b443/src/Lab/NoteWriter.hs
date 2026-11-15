module Lab.NoteWriter (main) where

import System.Directory (createDirectoryIfMissing)
import System.FilePath ((<.>), (</>))
import System.IO

notesDir :: FilePath
notesDir = "/srv/lab/notes"

-- Reads a barcode and a note from the bench terminal and files the note.
main :: IO ()
main = do
  createDirectoryIfMissing True notesDir
  hSetBuffering stdout NoBuffering
  putStr "barcode: "
  barcode <- getLine
  putStr "note: "
  note <- getLine
  appendNote barcode note

appendNote :: String -> String -> IO ()
appendNote barcode note =
  withFile (notesDir </> barcode <.> "txt") AppendMode $ \h -> do
    hPutStrLn h note
    hFlush h
