{-# LANGUAGE OverloadedStrings #-}
module ProfileBanner (main) where

import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Lucid
import Snap.Core
import Snap.Http.Server (quickHttpServe)

main :: IO ()
main = quickHttpServe $ route [("banner", method GET bannerHandler)]

bannerHandler :: Snap ()
bannerHandler = do
  cookie <- getCookie "display_name"
  let displayName = maybe "Guest" (TE.decodeLatin1 . cookieValue) cookie
  modifyResponse (setContentType "text/html; charset=utf-8")
  writeLBS (renderBS (banner displayName))

banner :: Text -> Html ()
banner displayName = html_ $ body_ $ do
  div_ [class_ "banner"] $ do
    span_ "Welcome back, "
    strong_ (toHtmlRaw displayName)
  p_ "Your dashboard is ready."
