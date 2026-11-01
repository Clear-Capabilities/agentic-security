{-# LANGUAGE OverloadedStrings, TypeApplications #-}
module MemberDirectory (postDirectorySearchR) where

import Data.Aeson (Value)
import Data.Text (Text)
import Database.Esqueleto.Experimental
import Database.Persist.Sql (SqlPersistT)
import Yesod.Core
import Yesod.Form
import Foundation (Handler, Member(..), EntityField(..))

searchMembers :: Text -> SqlPersistT Handler [Entity Member]
searchMembers term = select $ do
  m <- from (table @Member)
  where_ (m ^. MemberName `like` (%) ++. val term ++. (%))
  orderBy [asc (m ^. MemberName)]
  limit 25
  pure m

postDirectorySearchR :: Handler Value
postDirectorySearchR = do
  term <- runInputPost (ireq textField "q")
  members <- runDB (searchMembers term)
  returnJson [ memberName m | Entity _ m <- members ]
