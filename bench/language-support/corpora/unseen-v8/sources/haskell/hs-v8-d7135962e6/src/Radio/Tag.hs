{-# LANGUAGE OverloadedStrings #-}
module Radio.Tag (tagRoutes, tagSegment) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy as TL
import System.Exit (ExitCode (..))
import System.Process (readProcessWithExitCode)
import Web.Scotty

-- Writes the programme title into an already transcoded segment.
tagSegment :: FilePath -> String -> IO ExitCode
tagSegment segmentPath title = do
  (code, _, _) <- readProcessWithExitCode "ffmpeg" (ffmpegArgs segmentPath title) ""
  pure code

ffmpegArgs :: FilePath -> String -> [String]
ffmpegArgs path title =
  [ "-loglevel", "error", "-y"
  , "-i", path
  , "-metadata", "title=" ++ title
  , "-codec", "copy"
  , path ++ ".tagged.mp3"
  ]

tagRoutes :: (Int -> IO (Maybe FilePath)) -> ScottyM ()
tagRoutes locateSegment =
  post "/segments/:id/title" $ do
    segmentId <- param "id"
    title <- param "title"
    located <- liftIO (locateSegment segmentId)
    case located of
      Nothing -> text "unknown segment"
      Just path -> do
        code <- liftIO (tagSegment path (TL.unpack title))
        text (if code == ExitSuccess then "tagged" else "ffmpeg reported a problem")
