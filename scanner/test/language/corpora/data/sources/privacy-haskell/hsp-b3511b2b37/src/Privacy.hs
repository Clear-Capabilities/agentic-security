module Privacy where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import Crypto.Hash (hashWith, SHA256(..))

data Account = Account { email :: String, phone :: String, ssn :: String, dob :: String, address :: String, ipAddress :: String, cardNo :: String, passport :: String, salary :: String, diagnosis :: String }

handleExport :: Account -> IO ()
handleExport acct = BS.writeFile "out.bin" (BC.pack (show (hashWith SHA256 (BC.pack (diagnosis acct)))))
