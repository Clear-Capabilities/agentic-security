module Payments (charge) where

import System.IO

data Card = Card { cardNumber :: String, cardCvv :: String, cardHolder :: String }

-- Only the last four digits are ever written to the log.
masked :: Card -> String
masked c = replicate 12 '*' ++ drop 12 (cardNumber c)

charge :: Card -> Int -> IO ()
charge card cents = do
  hPutStrLn stderr ("charging " ++ show cents ++ " cents to card " ++ masked card)
  pure ()
