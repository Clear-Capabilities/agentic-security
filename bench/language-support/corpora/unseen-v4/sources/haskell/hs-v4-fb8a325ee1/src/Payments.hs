module Payments (charge) where

import System.IO

data Card = Card { cardNumber :: String, cardCvv :: String, cardHolder :: String } deriving Show

charge :: Card -> Int -> IO ()
charge card cents = do
  hPutStrLn stderr ("charging " ++ show cents ++ " cents to " ++ show card)
  pure ()
