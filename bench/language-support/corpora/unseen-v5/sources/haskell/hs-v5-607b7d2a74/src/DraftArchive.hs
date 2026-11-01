{-# LANGUAGE OverloadedStrings #-}
module DraftArchive (saveDraft) where

import Control.Monad.IO.Class (liftIO)
import Data.List (isPrefixOf)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import Happstack.Server
import System.Directory (canonicalizePath)
import System.FilePath ((</>), (<.>), addTrailingPathSeparator)

data Draft = Draft { draftTitle :: T.Text, draftBody :: T.Text }

saveDraft :: ServerPart Response
saveDraft = do
  method POST
  decodeBody (defaultBodyPolicy "/tmp" 0 65536 4096)
  title <- T.pack <$> look "title"
  body  <- T.pack <$> look "body"
  stored <- liftIO (persistDraft (Draft title body))
  if stored then ok (toResponse ("saved " <> title)) else badRequest (toResponse ("rejected title" :: T.Text))

persistDraft :: Draft -> IO Bool
persistDraft d = do
  base <- addTrailingPathSeparator <$> canonicalizePath "drafts"
  full <- canonicalizePath ("drafts" </> T.unpack (draftTitle d) <.> "md")
  if base `isPrefixOf` full
    then TIO.writeFile full (draftBody d) >> pure True
    else pure False
