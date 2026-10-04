module Privacy where

import qualified Data.Text as T
import qualified Data.Text.IO as TIO

data Account = Account { email :: String, phone :: String, ssn :: String, dob :: String, address :: String, ipAddress :: String, cardNo :: String, passport :: String, salary :: String, diagnosis :: String }

handleExport :: Account -> IO ()
handleExport acct = TIO.putStrLn (T.pack (diagnosis acct ++ "/dob"))
