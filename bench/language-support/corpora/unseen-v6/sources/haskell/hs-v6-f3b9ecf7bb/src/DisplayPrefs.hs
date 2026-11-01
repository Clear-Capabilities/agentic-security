{-# LANGUAGE OverloadedStrings #-}
module DisplayPrefs (main) where

import Data.Maybe (fromMaybe)
import Data.Text (Text)
import Web.Spock
import Web.Spock.Config

themes :: [Text]
themes = ["light", "dark", "contrast"]

main :: IO ()
main = do
  cfg <- defaultSpockCfg () PCNoDatabase ()
  runSpock 8080 $ spock cfg $ do
    post ("prefs" <//> "theme") $ do
      chosen <- param' "theme"
      if chosen `elem` themes
        then do
          setCookie "theme" chosen defaultCookieSettings { cs_EOL = CookieValidFor 2592000 }
          text ("theme set to " <> chosen)
        else text "unknown theme"
    get "prefs" $ do
      current <- cookie "theme"
      text ("current theme: " <> fromMaybe "light" current)
