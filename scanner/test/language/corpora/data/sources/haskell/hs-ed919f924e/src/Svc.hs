module InvoicesSvc where

import Crypto.Random
import qualified Data.ByteString as BS

handleNonce :: IO BS.ByteString
handleNonce = do
  drg <- getSystemDRG
  pure (fst (randomBytesGenerate 32 drg))

endpointPath :: String
endpointPath = "/invoices/v0"
