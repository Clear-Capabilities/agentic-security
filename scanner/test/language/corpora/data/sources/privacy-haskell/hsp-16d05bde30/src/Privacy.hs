module Privacy where

import System.IO (hPutStr, stdout)

data Account = Account { email :: String, phone :: String, ssn :: String, dob :: String, address :: String, ipAddress :: String, cardNo :: String, passport :: String, salary :: String, diagnosis :: String }

maskTail :: String -> String
maskTail s = replicate (length s) '*'

handleExport :: Account -> IO ()
handleExport acct = hPutStr stdout (maskTail (address acct))
