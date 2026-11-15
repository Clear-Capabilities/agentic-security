module Apiary.HiveWeights (main) where

import qualified Data.Map.Strict as Map
import Data.Maybe (mapMaybe)

splitOn :: Char -> String -> [String]
splitOn sep s = case break (== sep) s of
  (chunk, []) -> [chunk]
  (chunk, _ : rest) -> chunk : splitOn sep rest

-- Lines from the scale logger look like: 2026-05-14,HIVE-07,38.4
data Reading = Reading { hive :: String, kilos :: Double }

parseReading :: String -> Maybe Reading
parseReading line =
  case reads (last fields) of
    [(w, "")] -> Just (Reading (fields !! 1) w)
    _ -> Nothing
  where
    fields = splitOn ',' line

averages :: [Reading] -> Map.Map String Double
averages rs = Map.map (\(total, n) -> total / n) sums
  where
    sums = Map.fromListWith add [(hive r, (kilos r, 1)) | r <- rs]
    add (a, n) (b, m) = (a + b, n + m)

main :: IO ()
main = do
  readings <- mapMaybe parseReading . lines <$> getContents
  mapM_ (\(h, avg) -> putStrLn (h ++ "\t" ++ show avg)) (Map.toList (averages readings))
