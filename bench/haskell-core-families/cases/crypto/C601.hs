module C601 where
import System.Random

newToken :: IO Int
newToken = randomRIO (0, 999999)
