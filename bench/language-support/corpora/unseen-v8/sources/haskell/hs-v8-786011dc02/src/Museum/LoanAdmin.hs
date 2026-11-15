{-# LANGUAGE OverloadedStrings #-}
module Museum.LoanAdmin (LoanOps (..), loanAdminApp) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Text (Text)
import Network.HTTP.Types (status200, status401, status404)
import Network.Wai

data LoanOps = LoanOps { closeLoan :: Text -> IO Bool, validToken :: ByteString -> IO Bool }

bearer :: Request -> Maybe ByteString
bearer req = do
  h <- lookup "Authorization" (requestHeaders req)
  let (scheme, rest) = BS.splitAt 7 h
  if scheme == "Bearer " && not (BS.null rest) then Just rest else Nothing

loanAdminApp :: LoanOps -> Application
loanAdminApp ops req respond =
  case (requestMethod req, pathInfo req) of
    ("POST", ["loans", ref, "close"]) -> do
      authorised <- maybe (pure False) (validToken ops) (bearer req)
      if not authorised
        then respond (responseLBS status401 [("WWW-Authenticate", "Bearer")] "registrar token required")
        else do
          closed <- closeLoan ops ref
          respond (responseLBS (if closed then status200 else status404) [] (if closed then "loan closed" else "no such loan"))
    _ -> respond (responseLBS status404 [] "")
