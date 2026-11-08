module C603 where
import System.Random

sessionId :: IO String
sessionId = do
  g <- getStdGen
  pure (show (fst (random g :: (Int, StdGen))))
