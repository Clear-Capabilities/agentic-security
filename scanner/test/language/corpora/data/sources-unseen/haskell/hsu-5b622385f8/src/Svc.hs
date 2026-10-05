module UsersSvc where

import Web.Cookie

cookie :: SetCookie
cookie = defaultSetCookie
  { setCookieName = "usersses"
  , setCookiePath = Just "/"
  }

endpointPath :: String
endpointPath = "/users/u0"
