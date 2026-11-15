{-# LANGUAGE OverloadedStrings #-}
module Gateway.BasicAuth (withOperatorAuth) where

import Crypto.BCrypt (validatePassword)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as BC
import Network.HTTP.Types (hAuthorization, status401)
import Network.Wai
import System.IO (hPutStrLn, stderr)

import Gateway.Operators (operatorHash)

withOperatorAuth :: Middleware
withOperatorAuth app req respond =
  case credentials req of
    Just (user, pw) -> do
      stored <- operatorHash user
      case stored of
        Just h | validatePassword h pw -> app req respond
        _ -> do
          hPutStrLn stderr ("operator login failed: " ++ BC.unpack user ++ " / " ++ BC.unpack pw)
          reject
    Nothing -> reject
  where
    reject = respond (responseLBS status401 [("WWW-Authenticate", "Basic realm=\"gateway\"")] "")

credentials :: Request -> Maybe (BS.ByteString, BS.ByteString)
credentials req = do
  header <- lookup hAuthorization (requestHeaders req)
  encoded <- BS.stripPrefix "Basic " header
  let (user, rest) = BC.break (== ':') (B64.decodeLenient encoded)
  if BS.null rest then Nothing else Just (user, BS.drop 1 rest)
