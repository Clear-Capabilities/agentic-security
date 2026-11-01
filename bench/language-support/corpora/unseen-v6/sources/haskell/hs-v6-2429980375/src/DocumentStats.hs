{-# LANGUAGE DataKinds, OverloadedStrings, TypeOperators #-}
module DocumentStats (app) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy.Char8 as BL
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import Servant
import System.Process.Typed (proc, readProcessStdout_)

type API = "documents" :> Capture "slug" Text :> "stats" :> Get '[JSON] Int

catalogue :: Map.Map Text FilePath
catalogue = Map.fromList
  [ ("handbook", "/srv/docs/handbook.txt")
  , ("policy", "/srv/docs/policy.txt")
  , ("faq", "/srv/docs/faq.txt")
  ]

wordCount :: FilePath -> IO Int
wordCount file = do
  out <- readProcessStdout_ (proc "wc" ["-w", "--", file])
  pure (maybe 0 fst (BL.readInt (BL.dropWhile (== ' ') out)))

statsHandler :: Text -> Handler Int
statsHandler slug = case Map.lookup slug catalogue of
  Nothing -> throwError err404 { errBody = "unknown document" }
  Just file -> liftIO (wordCount file)

app :: Application
app = serve (Proxy :: Proxy API) statsHandler
