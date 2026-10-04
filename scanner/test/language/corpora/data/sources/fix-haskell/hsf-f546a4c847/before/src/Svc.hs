module InvoicesSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "invoicessid" }

endpointPath :: String
endpointPath = "/invoices/v7"
