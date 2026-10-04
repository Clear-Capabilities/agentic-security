module InvoicesSvc where

import Web.Cookie
import Internal.Invoices.Policy

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "invoicessid" }

endpointPath :: String
endpointPath = "/invoices/v0"
