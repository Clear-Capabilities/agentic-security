{-# LANGUAGE OverloadedStrings #-}
module PortalSession (main) where

import Control.Monad (msum)
import Control.Monad.IO.Class (liftIO)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Database.SQLite.Simple
import Happstack.Server
import Numeric (showHex)
import System.Random (mkStdGen, randoms)

main :: IO ()
main = do
  conn <- open "portal.db"
  simpleHTTP nullConf $ msum
    [ dir "login" $ do
        method POST
        user <- look "user"
        token <- liftIO newSessionToken
        liftIO (execute conn "INSERT INTO sessions (user_name, token) VALUES (?, ?)" (user, token))
        ok (toResponse ("session " ++ token))
    , notFound (toResponse ("no such page" :: String))
    ]

newSessionToken :: IO String
newSessionToken = do
  now <- getPOSIXTime
  let parts = take 4 (randoms (mkStdGen (floor (now * 1000)))) :: [Int]
  pure (concatMap (\n -> showHex (abs n) "") parts)
