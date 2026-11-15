{-# LANGUAGE OverloadedStrings #-}
module Fleet.ProviderFetch (fetchPositions) where

import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy as BL
import Network.HTTP.Client

-- Telemetry providers the fleet office has a contract with.
approvedHosts :: [B8.ByteString]
approvedHosts = ["telemetry.northroad.example", "api.vantrack.example", "feeds.haulnet.example"]

fetchPositions :: Manager -> String -> IO (Either String BL.ByteString)
fetchPositions mgr providerUrl =
  case parseRequest providerUrl of
    Nothing -> pure (Left "unreadable provider url")
    Just req
      | secure req && host req `elem` approvedHosts && port req == 443 ->
          Right . responseBody <$> httpLbs req mgr
      | otherwise -> pure (Left "provider not on the approved list")
