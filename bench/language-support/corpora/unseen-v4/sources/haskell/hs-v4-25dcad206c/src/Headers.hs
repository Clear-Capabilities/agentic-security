module Headers (bearerToken) where

import Network.Wai
import Network.HTTP.Types.Header (hAuthorization)
import qualified Data.ByteString.Char8 as B

bearerToken :: Request -> B.ByteString
bearerToken req = B.words auth !! 1
  where
    auth = maybe B.empty id (lookup hAuthorization (requestHeaders req))
