{-# LANGUAGE OverloadedStrings #-}
module UptimeCheck (uptimeApp) where

import qualified Data.ByteString.Lazy.Char8 as BL
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Network.HTTP.Types (status200, status400)
import Network.Wai
import Turtle (ExitCode (..), empty, shell)

uptimeApp :: Application
uptimeApp req respond =
  case lookup "host" (queryString req) of
    Just (Just raw) -> do
      code <- probe (TE.decodeLatin1 raw)
      respond (responseLBS status200 [("Content-Type", "text/plain")] (reportLine code))
    _ ->
      respond (responseLBS status400 [] "host parameter required")

probe :: Text -> IO ExitCode
probe host = shell ("ping -c 1 -W 2 " <> host) empty

reportLine :: ExitCode -> BL.ByteString
reportLine ExitSuccess     = "up"
reportLine (ExitFailure _) = "down"
