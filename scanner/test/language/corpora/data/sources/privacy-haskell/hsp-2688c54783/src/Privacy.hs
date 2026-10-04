module Privacy where

import System.IO (hPutStr, stdout)

data Account = Account { email :: String, phone :: String, ssn :: String, dob :: String, address :: String, ipAddress :: String, cardNo :: String, passport :: String, salary :: String, diagnosis :: String }

handleExport :: Account -> IO ()
handleExport acct = hPutStr stdout (show (null (email acct) || length (email acct) > 64))
