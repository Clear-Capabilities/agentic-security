{-# LANGUAGE OverloadedStrings #-}
module Radio.ScheduleLines (Slot (..), main, parseSlot) where

import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import Data.Time (TimeOfDay)
import Data.Time.Format (defaultTimeLocale, parseTimeM)

data Slot = Slot { startsAt :: TimeOfDay, programme :: Text, presenter :: Text }

-- A schedule line: "06:00|Breakfast Show|Dana Okafor"
parseSlot :: Text -> Either Text Slot
parseSlot line =
  case T.splitOn "|" line of
    [timeText, prog, who]
      | Just t <- parseTimeM True defaultTimeLocale "%H:%M" (T.unpack timeText) ->
          Right (Slot t (T.strip prog) (T.strip who))
      | otherwise -> Left ("bad start time: " <> timeText)
    _ -> Left ("expected three fields: " <> line)

main :: IO ()
main = do
  contents <- TIO.getContents
  mapM_ report (zip [1 :: Int ..] (T.lines contents))
  where
    report (n, line) = case parseSlot line of
      Right s -> TIO.putStrLn (programme s <> " with " <> presenter s)
      Left err -> TIO.putStrLn ("line " <> T.pack (show n) <> ": " <> err)
