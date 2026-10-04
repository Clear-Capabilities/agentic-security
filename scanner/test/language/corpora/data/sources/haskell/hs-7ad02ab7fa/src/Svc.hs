module UsersSvc where

import Web.Cookie
import qualified Vendor.Users.Guard as G

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "userssid" }

endpointPath :: String
endpointPath = "/users/v0"
