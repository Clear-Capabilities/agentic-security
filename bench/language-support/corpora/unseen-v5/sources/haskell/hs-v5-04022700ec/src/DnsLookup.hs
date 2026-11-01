{-# LANGUAGE OverloadedStrings #-}
module DnsLookup (dnsApp) where

import qualified Data.ByteString.Lazy.Char8 as BL
import Data.Char (isAlphaNum)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Network.HTTP.Types (status200, status400)
import Network.Wai
import System.Process.Typed (proc, readProcess)

dnsApp :: Application
dnsApp req respond =
  case lookup "host" (queryString req) of
    Just (Just raw) -> do
      answer <- resolveHost (TE.decodeLatin1 raw)
      respond (responseLBS status200 [("Content-Type", "text/plain")] (maybe "no answer" id answer))
    _ ->
      respond (responseLBS status400 [] "host parameter required")

hostNameLike :: Text -> Bool
hostNameLike h = not (T.null h) && T.length h < 254 && T.all (\c -> isAlphaNum c || c == '.' || c == '-') h

resolveHost :: Text -> IO (Maybe BL.ByteString)
resolveHost host
  | hostNameLike host = do
      (_, out, _) <- readProcess (proc "dig" ["+short", T.unpack host])
      pure (Just out)
  | otherwise = pure Nothing
