{-# LANGUAGE OverloadedStrings #-}
module DraftStore (saveDraft) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import Happstack.Server
import System.FilePath ((</>), (<.>))

data Draft = Draft { draftTitle :: T.Text, draftBody :: T.Text }

saveDraft :: ServerPart Response
saveDraft = do
  method POST
  decodeBody (defaultBodyPolicy "/tmp" 0 65536 4096)
  title <- T.pack <$> look "title"
  body  <- T.pack <$> look "body"
  let draft = Draft title body
  liftIO (persistDraft draft)
  ok (toResponse ("saved " <> draftTitle draft))

persistDraft :: Draft -> IO ()
persistDraft d =
  TIO.writeFile ("drafts" </> T.unpack (draftTitle d) <.> "md") (draftBody d)
