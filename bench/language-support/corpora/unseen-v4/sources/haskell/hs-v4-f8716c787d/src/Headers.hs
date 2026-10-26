module Headers (bearerToken) where

import Network.Wai
import Network.HTTP.Types.Header (hAuthorization)
import qualified Data.ByteString.Char8 as B

bearerToken :: Request -> Maybe B.ByteString
bearerToken req =
  case B.words =<< maybe [] pure (lookup hAuthorization (requestHeaders req)) of
    ["Bearer", tok] -> Just tok
    _               -> Nothing
