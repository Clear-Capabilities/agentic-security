{-# LANGUAGE OverloadedStrings #-}
module Catalogue.IsbnLookup (lookupIsbn) where

import Control.Lens ((&), (.~), (^.))
import qualified Data.ByteString.Lazy as BL
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import qualified Network.Wreq as Wreq

data Source = OpenShelf | NationalUnion | PublisherDirect
  deriving (Eq, Ord, Show)

sources :: Map.Map Text (Source, String)
sources = Map.fromList
  [ ("openshelf", (OpenShelf, "https://openshelf.example/api/isbn"))
  , ("union", (NationalUnion, "https://union-catalogue.example/lookup"))
  , ("publisher", (PublisherDirect, "https://meta.publishers.example/isbn"))
  ]

lookupIsbn :: Text -> Text -> IO (Either String BL.ByteString)
lookupIsbn sourceName isbn =
  case Map.lookup (T.toLower sourceName) sources of
    Nothing -> pure (Left ("unknown source: " ++ T.unpack sourceName))
    Just (_, base) -> do
      let opts = Wreq.defaults & Wreq.param "isbn" .~ [isbn]
      resp <- Wreq.getWith opts base
      pure (Right (resp ^. Wreq.responseBody))
