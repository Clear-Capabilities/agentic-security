{-# LANGUAGE DataKinds, OverloadedStrings, TypeOperators #-}
module LogViewer (app) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy.Char8 as BL
import Data.List (isPrefixOf)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import Servant
import System.Directory (canonicalizePath)
import System.FilePath (addTrailingPathSeparator, (</>))

type API = "logs" :> QueryParam "file" Text :> Get '[PlainText] Text

logRoot :: FilePath
logRoot = "/var/log/app"

resolveLog :: Text -> IO (Either String FilePath)
resolveLog name = do
  base <- addTrailingPathSeparator <$> canonicalizePath logRoot
  full <- canonicalizePath (logRoot </> T.unpack name)
  pure (if base `isPrefixOf` full then Right full else Left "outside the log directory")

logHandler :: Maybe Text -> Handler Text
logHandler Nothing = throwError err400 { errBody = "file parameter required" }
logHandler (Just name) = do
  resolved <- liftIO (resolveLog name)
  case resolved of
    Left reason -> throwError err403 { errBody = BL.pack reason }
    Right file -> liftIO (TIO.readFile file)

app :: Application
app = serve (Proxy :: Proxy API) logHandler
