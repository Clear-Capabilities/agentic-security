module Privacy where

import Crypto.Hash (hashWith, SHA256(..))
import qualified Data.ByteString.Char8 as BC

data Account = Account { email :: String, phone :: String, ssn :: String, dob :: String, address :: String, ipAddress :: String, cardNo :: String, passport :: String, salary :: String, diagnosis :: String }

handleExport :: Account -> IO ()
handleExport acct = appendFile "crm.log" (show (hashWith SHA256 (BC.pack (salary acct))))
