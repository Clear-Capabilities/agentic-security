module Catalogue.FineReceipt (FinePayment (..), logFinePayment) where

import System.IO (hPutStrLn, stderr)

data FinePayment = FinePayment { patronId :: String, paymentCard :: String, pence :: Int }

maskPan :: String -> String
maskPan pan = replicate (length pan - 4) '*' ++ drop (length pan - 4) pan

logFinePayment :: FinePayment -> IO ()
logFinePayment p =
  hPutStrLn stderr ("fine paid by patron " ++ patronId p ++ " card " ++ maskPan (paymentCard p) ++ " amount " ++ show (pence p))
