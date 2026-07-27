# GAPS.md — parse failures and measured shortfalls in the proof corpus

Generated from the per-target IR-stats sidecars written by the runner
(`AGENTIC_SECURITY_IR_STATS` → `bench/proof-corpus/results/raw/<id>/ir-stats.json`,
each sidecar's per-language `failures[]` array) plus
`bench/proof-corpus/results/summary.json`. Regenerate by re-running
`node bench/proof-corpus/runner.mjs --only ghost,superset,godot` and re-reading
those two files.

This file exists because `docs/PROOF_CORPUS_PRD.md` §12 criterion 2 promises the
files that fail to parse are enumerated, not merely counted. A campaign of this
size that reports zero gaps has a broken harness, not a perfect scanner.

**Disclosure boundary (PRD §9.1):** these are source PATHS in public repositories
at pinned public commits, and say only which files OUR parser could not build IR
for. No findings, no snippets, and no vulnerability claims about third-party code
appear here — those stay in the gitignored `results/raw/`.

## Run provenance

| Target | Commit | Scanned path | Parse coverage | Failing files |
|---|---|---|---|---|
| ghost | `7da28a03b9c72fa2cc656f5f926230bae09fd684` | . | 4023/4271 (94%) | 248 |
| superset | `e1ffa53d9b4926f2ac7fe8c83c5f890fd621f3c8` | . | 4083/4086 (100%) | 3 |
| godot | `159701651ad44335691dcbd632d8074307074c7b` | core, modules, scene, servers, editor | 3391/3399 (100%) | 8 |

## ghost

### javascript — 4023/4271 parsed, 248 failing

The sidecar caps its listed sample at 200 paths per language (`ir-stats.js`
`_MAX_FAILURES_LISTED`); the counts above are exact, the list below is the
first 200 of 248.

- `apps/ember-admin/app/components/aspect-ratio-box.js`
- `apps/ember-admin/app/components/editor/email-size-warning.js`
- `apps/ember-admin/app/components/editor/modals/delete-snippet.js`
- `apps/ember-admin/app/components/editor/modals/preview.js`
- `apps/ember-admin/app/components/editor/modals/preview/browser.js`
- `apps/ember-admin/app/components/editor/modals/preview/email.js`
- `apps/ember-admin/app/components/editor/modals/preview/email/email-subject.js`
- `apps/ember-admin/app/components/editor/modals/preview/social.js`
- `apps/ember-admin/app/components/editor/modals/publish-flow.js`
- `apps/ember-admin/app/components/editor/modals/publish-flow/complete-with-email-error.js`
- `apps/ember-admin/app/components/editor/modals/publish-flow/confirm.js`
- `apps/ember-admin/app/components/editor/modals/publish-flow/options.js`
- `apps/ember-admin/app/components/editor/modals/re-authenticate.js`
- `apps/ember-admin/app/components/editor/modals/re-verify.js`
- `apps/ember-admin/app/components/editor/modals/update-flow.js`
- `apps/ember-admin/app/components/editor/modals/update-snippet.js`
- `apps/ember-admin/app/components/editor/publish-management.js`
- `apps/ember-admin/app/components/editor/publish-options/publish-at.js`
- `apps/ember-admin/app/components/editor/publish-options/publish-type.js`
- `apps/ember-admin/app/components/gh-alert.js`
- `apps/ember-admin/app/components/gh-alerts.js`
- `apps/ember-admin/app/components/gh-authors-token-input.js`
- `apps/ember-admin/app/components/gh-basic-dropdown.js`
- `apps/ember-admin/app/components/gh-billing-iframe.js`
- `apps/ember-admin/app/components/gh-billing-modal.js`
- `apps/ember-admin/app/components/gh-blog-url.js`
- `apps/ember-admin/app/components/gh-browser-preview.js`
- `apps/ember-admin/app/components/gh-canvas-header.js`
- `apps/ember-admin/app/components/gh-cm-editor.js`
- `apps/ember-admin/app/components/gh-context-menu.js`
- `apps/ember-admin/app/components/gh-custom-view-title.js`
- `apps/ember-admin/app/components/gh-date-picker.js`
- `apps/ember-admin/app/components/gh-date-time-picker.js`
- `apps/ember-admin/app/components/gh-dropdown-button.js`
- `apps/ember-admin/app/components/gh-dropdown.js`
- `apps/ember-admin/app/components/gh-editor-feature-image.js`
- `apps/ember-admin/app/components/gh-editor-post-status.js`
- `apps/ember-admin/app/components/gh-editor.js`
- `apps/ember-admin/app/components/gh-email-preview-link.js`
- `apps/ember-admin/app/components/gh-explore-iframe.js`
- `apps/ember-admin/app/components/gh-explore-modal.js`
- `apps/ember-admin/app/components/gh-facebook-url-input.js`
- `apps/ember-admin/app/components/gh-file-input.js`
- `apps/ember-admin/app/components/gh-html-iframe.js`
- `apps/ember-admin/app/components/gh-infinity-loader.js`
- `apps/ember-admin/app/components/gh-input-with-select/index.js`
- `apps/ember-admin/app/components/gh-input-with-select/trigger.js`
- `apps/ember-admin/app/components/gh-koenig-editor-lexical.js`
- `apps/ember-admin/app/components/gh-loading-spinner.js`
- `apps/ember-admin/app/components/gh-member-details.js`
- `apps/ember-admin/app/components/gh-member-label-input.js`
- `apps/ember-admin/app/components/gh-member-settings-form.js`
- `apps/ember-admin/app/components/gh-members-filter-count.js`
- `apps/ember-admin/app/components/gh-members-recipient-select.js`
- `apps/ember-admin/app/components/gh-members-segment-count.js`
- `apps/ember-admin/app/components/gh-members-segment-select.js`
- `apps/ember-admin/app/components/gh-migrate-iframe.js`
- `apps/ember-admin/app/components/gh-migrate-modal.js`
- `apps/ember-admin/app/components/gh-notification.js`
- `apps/ember-admin/app/components/gh-notifications.js`
- `apps/ember-admin/app/components/gh-paginated-options.js`
- `apps/ember-admin/app/components/gh-paginated-token-input.js`
- `apps/ember-admin/app/components/gh-post-settings-menu.js`
- `apps/ember-admin/app/components/gh-post-settings-menu/visibility-segment-select.js`
- `apps/ember-admin/app/components/gh-power-select/trigger.js`
- `apps/ember-admin/app/components/gh-progress-bar.js`
- `apps/ember-admin/app/components/gh-psm-authors-input.js`
- `apps/ember-admin/app/components/gh-psm-tags-input.js`
- `apps/ember-admin/app/components/gh-psm-template-select.js`
- `apps/ember-admin/app/components/gh-psm-visibility-input.js`
- `apps/ember-admin/app/components/gh-resource-select.js`
- `apps/ember-admin/app/components/gh-scroll-trigger.js`
- `apps/ember-admin/app/components/gh-search-input.js`
- `apps/ember-admin/app/components/gh-segment-token-input.js`
- `apps/ember-admin/app/components/gh-site-iframe.js`
- `apps/ember-admin/app/components/gh-tags-token-input.js`
- `apps/ember-admin/app/components/gh-text-input.js`
- `apps/ember-admin/app/components/gh-textarea.js`
- `apps/ember-admin/app/components/gh-theme-error-li.js`
- `apps/ember-admin/app/components/gh-token-input.js`
- `apps/ember-admin/app/components/gh-token-input/label-token.js`
- `apps/ember-admin/app/components/gh-token-input/select-multiple.js`
- `apps/ember-admin/app/components/gh-token-input/tag-token.js`
- `apps/ember-admin/app/components/gh-token-input/trigger.js`
- `apps/ember-admin/app/components/gh-trim-focus-input.js`
- `apps/ember-admin/app/components/gh-twitter-url-input.js`
- `apps/ember-admin/app/components/gh-unsplash-photo.js`
- `apps/ember-admin/app/components/gh-unsplash.js`
- `apps/ember-admin/app/components/gh-uploader.js`
- `apps/ember-admin/app/components/gh-url-input.js`
- `apps/ember-admin/app/components/gh-url-preview.js`
- `apps/ember-admin/app/components/gh-view-title.js`
- `apps/ember-admin/app/components/koenig-image-editor.js`
- `apps/ember-admin/app/components/koenig-lexical-editor-input.js`
- `apps/ember-admin/app/components/koenig-lexical-editor.js`
- `apps/ember-admin/app/components/member/activity-feed.js`
- `apps/ember-admin/app/components/member/newsletter-preference.js`
- `apps/ember-admin/app/components/member/subscription-detail-box.js`
- `apps/ember-admin/app/components/members-activity/event-type-filter.js`
- `apps/ember-admin/app/components/members-activity/member-filter.js`
- `apps/ember-admin/app/components/members-activity/table-row.js`
- `apps/ember-admin/app/components/members/modals/delete-member.js`
- `apps/ember-admin/app/components/members/modals/disable-commenting.js`
- `apps/ember-admin/app/components/members/modals/logout-member.js`
- `apps/ember-admin/app/components/modal-member-tier.js`
- `apps/ember-admin/app/components/modal-post-history.js`
- `apps/ember-admin/app/components/modal-post-success.js`
- `apps/ember-admin/app/components/modals/custom-view-form.js`
- `apps/ember-admin/app/components/modals/delete-post.js`
- `apps/ember-admin/app/components/modals/email-preview.js`
- `apps/ember-admin/app/components/modals/new-custom-integration.js`
- `apps/ember-admin/app/components/modals/restore-revision.js`
- `apps/ember-admin/app/components/modals/search.js`
- `apps/ember-admin/app/components/multi-list/item.js`
- `apps/ember-admin/app/components/multi-list/list.js`
- `apps/ember-admin/app/components/posts-list/content-filter.js`
- `apps/ember-admin/app/components/posts-list/context-menu.js`
- `apps/ember-admin/app/components/posts-list/list-item-analytics.js`
- `apps/ember-admin/app/components/posts-list/list-item.js`
- `apps/ember-admin/app/components/posts-list/list.js`
- `apps/ember-admin/app/components/posts-list/modals/add-tag.js`
- `apps/ember-admin/app/components/posts-list/modals/edit-posts-access.js`
- `apps/ember-admin/app/components/posts-list/selection-list.js`
- `apps/ember-admin/app/components/posts/debug.js`
- `apps/ember-admin/app/components/posts/debug/email-error-message.js`
- `apps/ember-admin/app/components/power-select-options-with-scroll.js`
- `apps/ember-admin/app/components/tabs/tab.js`
- `apps/ember-admin/app/components/tabs/tabs.js`
- `apps/ember-admin/app/components/tags/delete-tag-modal.js`
- `apps/ember-admin/app/components/tags/tag-form.js`
- `apps/ember-admin/app/controllers/application.js`
- `apps/ember-admin/app/controllers/explore.js`
- `apps/ember-admin/app/controllers/lexical-editor.js`
- `apps/ember-admin/app/controllers/lexical-editor/edit-loading.js`
- `apps/ember-admin/app/controllers/member.js`
- `apps/ember-admin/app/controllers/members-activity.js`
- `apps/ember-admin/app/controllers/migrate.js`
- `apps/ember-admin/app/controllers/pages-loading.js`
- `apps/ember-admin/app/controllers/pages.js`
- `apps/ember-admin/app/controllers/posts-loading.js`
- `apps/ember-admin/app/controllers/posts.js`
- `apps/ember-admin/app/controllers/reset.js`
- `apps/ember-admin/app/controllers/restore-posts.js`
- `apps/ember-admin/app/controllers/setup.js`
- `apps/ember-admin/app/controllers/signin-verify.js`
- `apps/ember-admin/app/controllers/signin.js`
- `apps/ember-admin/app/controllers/signup.js`
- `apps/ember-admin/app/controllers/site.js`
- `apps/ember-admin/app/controllers/tag.js`
- `apps/ember-admin/app/helpers/activity-feed-fetcher.js`
- `apps/ember-admin/app/helpers/currency-symbol.js`
- `apps/ember-admin/app/helpers/enable-developer-experiments.js`
- `apps/ember-admin/app/helpers/feature.js`
- `apps/ember-admin/app/helpers/full-email-address.js`
- `apps/ember-admin/app/helpers/get-setting.js`
- `apps/ember-admin/app/helpers/gh-format-post-time.js`
- `apps/ember-admin/app/helpers/history-event-fetcher.js`
- `apps/ember-admin/app/helpers/history-event-filter.js`
- `apps/ember-admin/app/helpers/is-moment-today.js`
- `apps/ember-admin/app/helpers/member-fetcher.js`
- `apps/ember-admin/app/helpers/members-count-fetcher.js`
- `apps/ember-admin/app/helpers/members-event-fetcher.js`
- `apps/ember-admin/app/helpers/members-event-filter.js`
- `apps/ember-admin/app/helpers/moment-site-tz.js`
- `apps/ember-admin/app/helpers/parse-member-event.js`
- `apps/ember-admin/app/helpers/publish-options.js`
- `apps/ember-admin/app/helpers/sender-email-address.js`
- `apps/ember-admin/app/helpers/site-icon-style.js`
- `apps/ember-admin/app/helpers/toggle-feature.js`
- `apps/ember-admin/app/models/newsletter.js`
- `apps/ember-admin/app/models/post-revision.js`
- `apps/ember-admin/app/modifiers/close-dropdowns-on-click.js`
- `apps/ember-admin/app/modifiers/movable.js`
- `apps/ember-admin/app/modifiers/on-resize.js`
- `apps/ember-admin/app/modifiers/on-scroll.js`
- `apps/ember-admin/app/modifiers/select-on-click.js`
- `apps/ember-admin/app/routes/admin.js`
- `apps/ember-admin/app/routes/authenticated.js`
- `apps/ember-admin/app/routes/dashboard.js`
- `apps/ember-admin/app/routes/designsandbox.js`
- `apps/ember-admin/app/routes/explore.js`
- `apps/ember-admin/app/routes/explore/index.js`
- `apps/ember-admin/app/routes/home.js`
- `apps/ember-admin/app/routes/lexical-editor/edit.js`
- `apps/ember-admin/app/routes/lexical-editor/new.js`
- `apps/ember-admin/app/routes/member.js`
- `apps/ember-admin/app/routes/migrate.js`
- `apps/ember-admin/app/routes/pages.js`
- `apps/ember-admin/app/routes/posts.js`
- `apps/ember-admin/app/routes/pro.js`
- `apps/ember-admin/app/routes/reset.js`
- `apps/ember-admin/app/routes/restore-posts.js`
- `apps/ember-admin/app/routes/setup.js`
- `apps/ember-admin/app/routes/setup/index.js`
- `apps/ember-admin/app/routes/signin.js`
- `apps/ember-admin/app/routes/signout.js`
- `apps/ember-admin/app/routes/signup.js`
- `apps/ember-admin/app/routes/tag.js`
- `apps/ember-admin/app/routes/unauthenticated.js`
- `apps/ember-admin/app/serializers/theme.js`

## superset

### javascript — 2613/2616 parsed, 3 failing

- `docs/src/types/apache-superset-core/index.d.ts`
- `scripts/check-type.js`
- `superset-frontend/packages/superset-ui-switchboard/src/switchboard.ts`

## godot

### csharp — 298/306 parsed, 8 failing

- `modules/mono/editor/GodotTools/GodotTools.ProjectEditor/DotNetSolution.cs`
- `modules/mono/editor/GodotTools/GodotTools/Build/BuildSystem.cs`
- `modules/mono/editor/GodotTools/GodotTools/GodotSharpEditor.cs`
- `modules/mono/editor/GodotTools/GodotTools/Ides/MessagingServer.cs`
- `modules/mono/glue/GodotSharp/GodotSharp/Core/Callable.generics.cs`
- `modules/mono/glue/GodotSharp/GodotSharp/Core/DebuggingUtils.cs`
- `modules/mono/glue/GodotSharp/GodotSharp/Core/DelegateUtils.cs`
- `modules/mono/glue/GodotSharp/GodotSharp/Core/StringExtensions.cs`

