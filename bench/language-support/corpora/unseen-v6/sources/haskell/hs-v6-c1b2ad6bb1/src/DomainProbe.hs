{-# LANGUAGE OverloadedStrings #-}
module DomainProbe (main) where

import Control.Monad.IO.Class (liftIO)
import Data.Char (isAlphaNum)
import Data.Text (Text)
import qualified Data.Text as T
import Network.HTTP.Types (status400, status404)
import Network.Wai.Handler.Warp (run)
import qualified Shelly as Sh
import Web.Twain

main :: IO ()
main = run 8080 $ foldr ($) (notFound missing) [ post "/slack/probe" probe ]

probe :: ResponderM a
probe = do
  domain <- param "text"
  if validDomain domain
    then do
      answer <- liftIO (lookupAddress (T.strip domain))
      send (text answer)
    else send (status status400 (text "a domain may contain letters, digits, dots and dashes"))

lookupAddress :: Text -> IO Text
lookupAddress domain = Sh.shelly (Sh.silently (Sh.run "dig" ["+short", domain]))

validDomain :: Text -> Bool
validDomain d = not (T.null d) && T.length d < 254 && T.all (\c -> isAlphaNum c || c == '.' || c == '-') (T.strip d)

missing :: ResponderM a
missing = send (status status404 (text "not found"))
