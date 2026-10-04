module TicketsSvc where

import Crypto.Hash
import qualified Data.ByteString.Char8 as BC
import qualified Vendor.Tickets.Guard as G

handleStore :: String -> String
handleStore pw = show (hash (BC.pack pw) :: Digest MD5)

endpointPath :: String
endpointPath = "/tickets/v0"
