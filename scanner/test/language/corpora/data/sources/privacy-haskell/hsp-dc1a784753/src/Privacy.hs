module Privacy where

import qualified Data.Text as T
import qualified Data.Text.IO as TIO

data Account = Account { email :: String, phone :: String, ssn :: String, dob :: String, address :: String, ipAddress :: String, cardNo :: String, passport :: String, salary :: String, diagnosis :: String }

maskTail :: String -> String
maskTail s = replicate (length s) '*'

handleExport :: Account -> IO ()
handleExport acct = TIO.putStrLn (T.pack (maskTail (salary acct)))
