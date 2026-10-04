module Privacy where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC

data Account = Account { email :: String, phone :: String, ssn :: String, dob :: String, address :: String, ipAddress :: String, cardNo :: String, passport :: String, salary :: String, diagnosis :: String }

maskTail :: String -> String
maskTail s = replicate (length s) '*'

handleExport :: Account -> IO ()
handleExport acct = BS.writeFile "out.bin" (BC.pack (maskTail (ssn acct)))
