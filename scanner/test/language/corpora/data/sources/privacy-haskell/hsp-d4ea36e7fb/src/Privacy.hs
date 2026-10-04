module Privacy where

import Control.Monad (void)
import Network.HTTP.Simple

data Account = Account { email :: String, phone :: String, ssn :: String, dob :: String, address :: String, ipAddress :: String, cardNo :: String, passport :: String, salary :: String, diagnosis :: String }

handleExport :: Account -> IO ()
handleExport acct = void (httpNoBody (setRequestBodyJSON (email acct ++ "/ssn") (parseRequest_ "POST https://t.example/ingest")))
