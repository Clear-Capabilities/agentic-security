{-# LANGUAGE OverloadedStrings #-}
module TokenRotation (main) where

import Colog (LogAction, logTextStdout, (<&))
import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import qualified Data.Text as T
import Network.HTTP.Types.Status (status401)
import Web.Spock
import Web.Spock.Config
import qualified Tokens

data ApiToken = ApiToken { tokenId :: Text, tokenSecret :: Text }

parseBearer :: Text -> Maybe ApiToken
parseBearer h = case T.words h of
  ["Bearer", value] | [i, s] <- T.splitOn "." value -> Just (ApiToken i s)
  _ -> Nothing

main :: IO ()
main = do
  cfg <- defaultSpockCfg () PCNoDatabase ()
  let logger = logTextStdout :: LogAction IO Text
  runSpock 8080 $ spock cfg $
    post ("tokens" <//> "rotate") $ do
      auth <- header "Authorization"
      case auth >>= parseBearer of
        Nothing -> setStatus status401 >> text "bearer token required"
        Just tok -> do
          liftIO (announceRotation logger tok)
          replacement <- liftIO (Tokens.rotate (tokenId tok) (tokenSecret tok))
          json replacement

announceRotation :: LogAction IO Text -> ApiToken -> IO ()
announceRotation logger tok = logger <& ("rotating token id=" <> tokenId tok)
