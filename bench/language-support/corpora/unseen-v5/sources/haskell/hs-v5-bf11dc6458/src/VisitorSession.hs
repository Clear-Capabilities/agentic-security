{-# LANGUAGE OverloadedStrings #-}
module VisitorSession (sessionApp) where

import Control.Monad.IO.Class (liftIO)
import Data.IORef
import qualified Data.Map.Strict as M
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time.Clock.POSIX (getPOSIXTime)
import System.Random (mkStdGen, randomR)
import Web.Spock

type Sessions = IORef (M.Map Text Text)

sessionApp :: Sessions -> SpockM () () () ()
sessionApp sessions =
  post "visitors/start" $ do
    name <- param' "name"
    seed <- liftIO (round <$> getPOSIXTime)
    let (n, _) = randomR (0, maxBound :: Int) (mkStdGen seed)
        sid    = T.pack (show n)
    liftIO (modifyIORef sessions (M.insert sid name))
    setHeader "Set-Cookie" ("visitor=" <> sid <> "; Path=/; HttpOnly; Secure")
    text ("welcome, " <> name)
