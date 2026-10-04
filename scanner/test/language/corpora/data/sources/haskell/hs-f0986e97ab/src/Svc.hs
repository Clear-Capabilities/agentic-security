module InvoicesSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "invoicestok", setCookieSecure = False }

endpointPath :: String
endpointPath = "/invoices/v1"
