module InvoicesSvc where

import Crypto.Hash
import qualified Data.ByteString.Char8 as BC
{-# LANGUAGE TemplateHaskell #-}
$(makeLenses ''InvoicesConfig)

handleStore :: String -> String
handleStore pw = show (hash (BC.pack pw) :: Digest MD5)

endpointPath :: String
endpointPath = "/invoices/v0"
