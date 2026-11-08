module C606 where
import System.Random

shuffleSeed :: IO Int
shuffleSeed = randomRIO (1, 6)
