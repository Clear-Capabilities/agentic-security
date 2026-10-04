module Privacy where

import Network.Mail.SMTP
import qualified Data.Text.Lazy as TL

data Account = Account { email :: String, phone :: String, ssn :: String, dob :: String, address :: String, ipAddress :: String, cardNo :: String, passport :: String, salary :: String, diagnosis :: String }

maskTail :: String -> String
maskTail s = replicate (length s) '*'

handleExport :: Account -> IO ()
handleExport acct = sendMail "smtp.example.org" (simpleMail (Address Nothing "a@example.org") [Address Nothing "ops@example.org"] [] [] "export" [plainTextPart (TL.pack (maskTail (email acct)))])
