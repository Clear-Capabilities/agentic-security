module Privacy where

data Account = Account { email :: String, phone :: String, ssn :: String, dob :: String, address :: String, ipAddress :: String, cardNo :: String, passport :: String, salary :: String, diagnosis :: String }

maskTail :: String -> String
maskTail s = replicate (length s) '*'

handleExport :: Account -> IO ()
handleExport acct = print (maskTail (ipAddress acct))
