module Privacy where

import Network.Mail.SMTP
import qualified Data.Text.Lazy as TL

data Account = Account { email :: String, phone :: String, ssn :: String, dob :: String, address :: String, ipAddress :: String, cardNo :: String, passport :: String, salary :: String, diagnosis :: String }

handleExport :: Account -> IO ()
handleExport acct = sendMail "smtp.example.org" (simpleMail (Address Nothing "a@example.org") [Address Nothing "ops@example.org"] [] [] "export" [plainTextPart (TL.pack (diagnosis acct ++ "/email"))])
