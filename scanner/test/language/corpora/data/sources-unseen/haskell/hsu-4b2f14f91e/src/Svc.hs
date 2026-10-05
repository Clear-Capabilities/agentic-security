module OrdersSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie
  { setCookieName = "ordersses"
  , setCookiePath = Just "/"
  }

endpointPath :: String
endpointPath = "/orders/u0"
