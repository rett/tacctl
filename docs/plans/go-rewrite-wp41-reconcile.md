# WP4.1: the bats suite reconciled with the Go tests

WP4.1 retired the bash tree (`lib/`, the delegation to bash) and made the bats
suite run against the Go binary only. Every bats test that drove bash
internals (it sourced `lib/` through `tacctl_source_lib`, ran `bash -c 'source
…'`, or was tagged `bash-only`) was deleted, moved, or rewritten. This
document maps each deleted test to the Go test (or remaining black-box bats
test) that replaces it, or to the drop reason of plan §2.3. WP4.3's parity
document absorbs it.

Method: an instrumented run of the whole suite against the Go binary with
`lib/` gone (a `command_not_found_handle` and a recording
`tacctl_source_lib` logged every test that reached a bash function), then a
test-by-test reading of each bats body against the Go tests (Go tests quote
the bats titles or name the file they port; the WP commit messages list the
ports). Every Go test named here exists and passes (`make test-go`).

Status words in the tables: a Go test name alone is a full port; **PARTIAL**
in the note means some assertions of the bats test are not repeated, and
says which; **DROP** is a §2.3 reason; "written in WP4.1" marks a Go test
added by this package because the bats test had no replacement.

## Counts

| | tests |
|---|---|
| bats tests before WP4.1 (against Go, `lib/` present) | 1530 |
| deleted with their whole file (26 files: 16 `tests/unit`, 9 `tests/integration`, `tests/e2e/install_seed.bats`) | 627 |
| deleted from files that stay (`backend_cli` 66, `listeners` 6, `backup` 5, `radius` 2, `scope_protocols` 2, `store_mutations` 2, `tiers` 2, `store_cli` 1, `config_radius` 1, `config_templates` 1) | 88 |
| moved to `tests/integration/fixtures.bats` (black-box helper tests; one rewritten to use the CLI) | 11 |
| added (`fixtures.bats`: the tmpenv sandbox guard, ported from `sanity.bats`) | 1 |
| rewritten for the Go binary (kept; listed below) | 23 |
| bats tests after WP4.1 | 816 |

New Go tests written by WP4.1 for bats tests with no or partial replacement:
see "Go tests added" below.

## Rewritten bats tests (kept, now Go-only)

| file | test | change |
|---|---|---|
| characterisation.bats | config defaults: prints the shipped defaults, byte for byte the embedded internal/conf/defaults.yaml | compared with `internal/conf/defaults.yaml` instead of the bash `conf_emit_defaults` |
| characterisation.bats | hash generate: needs no python3; a failing one on PATH is never run | replaces "without python3-bcrypt it says so" (§3.9 item 4): asserts the effect |
| characterisation.bats | config branch (6 tests) | the helper runs the binary with `TACCTL_TREE` only (the bash branch is gone) |
| config_radius.bats | the RADIUS templates ship in config/templates, which the binary embeds | grep of `lib/lifecycle.sh` replaced by the embed line and a render naming the built-in template |
| config_render.bats | config render: writes the config when there is none, records it, restarts the daemon | the `chown` stub assertion (bash only) removed; mode and content asserted (§3.6) |
| radius.bats | enable (Debian layout), enable (RHEL layout) | `chown` stub assertions removed (§3.6) |
| radius.bats | upgrade: an install from the release before the dictionary…, upgrade: nothing to do…, upgrade: a hand-edited artifact…, the next mutation after the code changed… | `pre_vendor_state` records the planted files with the new fixtures helper `rendered_record`/`rendered_forget` instead of the bash functions |
| radius.bats | disable…, re-enable…, uninstall (two tests), upgrade: the output reads in order | `enabled_list` reads `config get-list backends.enabled`; the bash `backends_select_present` probes removed (the selection is `internal/backend: TestPresentIsEnabledThenInstalled`); the upgrade-order test keeps only its Go branch |
| shim.bats | shim: one build recipe: --build, the install path, 'make build' and the Go upgrade use it | the shim is `bin/tacctl.sh` now; replaces the byte comparison of two copies of the recipe |
| fixtures.bats | load_store_fixture: commands read the placed store, also after an earlier one | `_completion-names scopes` instead of the bash `model_scopes` |

## Go tests added by WP4.1

For bats tests that had no Go replacement, or only a partial one:

| bats file | bats test | Go test |
|---|---|---|
| unit/privilege.bats | default_privileges_for_group: superuser → empty (priv 15 ceiling) | internal/policy: TestDefaultPrivilegesSuperuserIsEmpty |
| unit/privilege.bats | default_privileges_for_group: unknown group → empty | internal/policy: TestDefaultPrivilegesUnknownGroupIsEmpty |
| unit/privilege.bats | read_group_privileges: filters to one group's commands | internal/policy: TestReadGroupPrivilegesFiltersToOneGroup |
| unit/privilege.bats | write_group_privileges: replaces only the target group's list | internal/policy: TestWriteGroupPrivilegesReplacesOnlyTheTargetGroup |
| unit/render_radius.bats | listeners: the schema takes udp and udp6 for radius, auth or acct, and refuses tcp and 'both' | internal/conf: TestListenerSchemaRadiusTakesUDPAuthOrAcctAndRefusesTCPAndBoth |
| unit/render_tacacs.bats | check: operator command overrides in tacctl.yaml are part of the proof | internal/cli: TestStoreImportCheckOperatorCommandOverridesArePartOfTheProof |
| integration/upgrade_templates.bats | install over a templates directory that is already there keeps a customised template | internal/lifecycle: TestTemplatesInstallOverAnExistingDirectoryKeepsACustomisedTemplate |
| integration/upgrade_templates.bats | upgrade: a customised template is kept; the release's version goes beside it as .new, with a warning saying how to compare | internal/lifecycle: TestTemplatesACustomisedTemplateIsKeptAndAStaleNewIsReplaced |
| integration/upgrade_templates.bats | upgrade: re-running changes nothing; the only output beyond 'Unchanged' is the still-customised notice | internal/lifecycle: TestTemplatesReRunningChangesNothing |
| integration/upgrade_templates.bats | upgrade: a customised template that is brought back to the shipped one is recorded again and its .new goes | internal/lifecycle: TestTemplatesACustomisedTemplateBroughtBackIsRecordedAgain |
| integration/upgrade_templates.bats | manifest-less: a template that is an older shipped version is refreshed, and the manifest is written | internal/lifecycle: TestTemplatesManifestLessAnOlderShippedVersionIsRefreshed |
| integration/upgrade_templates.bats | manifest-less: a customised template is kept, with .new and the warning | internal/lifecycle: TestTemplatesManifestLessACustomisedTemplateIsKept |
| integration/upgrade_templates.bats | a template that is some other template's shipped content is not taken for a shipped version of its own | internal/lifecycle: TestTemplatesAnotherTemplatesShippedContentIsNotItsOwn |
| e2e/install_seed.bats | install: the mode and the generated secret are handed to the caller, not printed | internal/lifecycle: TestSeedTheGeneratedSecretIsOnNoCommandLine |
| e2e/install_seed.bats | install: the store holds the built-in groups, the seed users disabled, the root sink, and scope lab | internal/lifecycle: TestSeedTheBuiltinGroupsPrivLvl (+ existing TestSeedTheStoreHoldsTheBuiltinsTheSeedUsersAndScopeLab) |
| integration/upgrade_store_flip.bats | rollback: the next upgrade flips again and reuses the pre-store copy | internal/lifecycle: TestFlipAfterARollbackTheNextUpgradeFlipsAgainReusingThePreStoreCopy |
| integration/migrate_exec_service_name.bats | migrate exec->shell: with a store the file is left alone; the import and render do the healing | internal/lifecycle: TestMigrateExecWithAStoreTheRenderKeepsTheOperatorPrivLvl (+ existing TestMigrateExecWithAStoreTheFileIsLeftAlone) |
| integration/upgrade_restart.bats | upgrade --branch to a branch whose lib/ differs re-executes the new tacctl once; that run has nothing more to pull | internal/lifecycle: TestUpgradeBranchSwitchReportsAndReexecsOnce |
| integration/upgrade_restart.bats | a pull on the same branch that changes lib/ re-executes once; one that changes only README.md does not | internal/lifecycle: TestUpgradeAReadmeOnlyPullStillRebuildsBecauseTheBinaryIsNotHEAD (+ existing TestMatrixSelfUpdateReexecs for the first half) |
| e2e/install_seed.bats | install_readme: a checkout without README.md is not an error | internal/backend/tacacs: TestInstallAccountWithoutReadmeIsNotAnError |
| integration/units_convert.bats | not converted: the first settings change converts, keeping the other settings | internal/backend/tacacs: TestFirstSettingsChangeConvertsThenUnitsInstallHasNothingToImport |
| integration/upgrade_restart.bats | a binary rolled back after a failed restart keeps its mode | internal/backend/tacacs: TestUpgradeFailedRestartRollbackKeepsTheBinaryMode |
| integration/backend_cli.bats | tacacs service enable and disable act on every listener's unit | internal/backend/tacacs: TestServiceWholeBackendEnableAndDisableReachEveryListener |
| integration/backend_cli.bats | backend disable: tacacs, when another backend stays, stops and disables tacquito and keeps tacquito.yaml | internal/backend/tacacs: TestServiceWholeBackendStopAndDisable (+ internal/cli: TestBackendDisableTacacsWhenAnotherStays) |
| integration/backend_cli.bats | backend list: needs no store and does not write anything | internal/cli: TestSectionsBackendListNeedsNoStore |
| integration/backend_cli.bats | backend status: per backend, the service and each listener, tcp and udp probed apart | internal/cli: TestSectionsBackendStatusTCPAndUDPListeners |
| integration/backend_cli.bats | backend list and status are read-only commands | internal/cli: TestSectionsBackendListStatusReadOnlyWithTwo |
| integration/backend_cli.bats | store rollback: refused while another backend is enabled | internal/cli: TestSectionsStoreRollbackRefusedWithAnotherBackend |
| integration/backend_cli.bats | status: each backend gets a labelled section with all its lines | internal/cli: TestSectionsStatusEachBackendInItsSection |
| integration/backend_cli.bats | status: a drifted artifact is shown in its backend's section, and not twice | internal/cli: TestSectionsStatusDriftInItsBackendsSectionOnce |
| integration/backend_cli.bats | status: with one backend the IPv6 parity wording is unchanged | internal/cli: TestSectionsStatusOneBackendIPv6ParityWording |
| integration/backend_cli.bats | config validate: one backend, the plain lines as always | internal/cli: TestSectionsValidateOneBackendNoBlock |
| integration/backend_cli.bats | config validate: a block per backend; one backend's drift does not hide the other's state | internal/cli: TestSectionsValidateABlockPerBackendDrift |
| integration/backend_cli.bats | config validate: each backend's own render state is judged | internal/cli: TestSectionsValidateEachBackendsRenderState |
| integration/backend_cli.bats | config validate: a disabled backend's edited leftovers are not an error | internal/cli: TestSectionsValidateDisabledBackendsLeftovers |
| integration/backend_cli.bats | config validate: a store that cannot be rendered by one backend is that backend's error | internal/cli: TestSectionsValidateUnknownRenderStateIsOutOfDate |
| integration/backend_cli.bats | config show: one backend, the lines it always printed | internal/cli: TestSectionsShowOneBackend |
| integration/backend_cli.bats | config show: the listener's own port is probed, not 49 | internal/cli: TestSectionsShowProbesTheListenersOwnPort |
| integration/backend_cli.bats | config show: a block per backend, tcp and udp listeners probed apart | internal/cli: TestSectionsShowABlockPerBackend |
| integration/backend_cli.bats | log: one backend, no heading; the arguments pass through | internal/cli: TestSectionsLogOneBackendNoHeading |
| integration/backend_cli.bats | log clear: every enabled backend, each with its own confirmation, -y passed on | internal/cli: TestSectionsLogClearEveryBackend |
| integration/backend_cli.bats | backup restore: the backends a snapshot enables follow it | internal/cli: TestSectionsBackupRestoreBackendsFollowTheSnapshot |
| integration/migrate_dead_command_matches.bats | config validate: flags a hand-edited override whose match regex can never fire | internal/cli: TestSectionsValidateDeadRegexOverride |
| integration/upgrade_store_flip.bats | flip: afterwards the install is fully working: validate is clean, nothing drifted, mutations apply | internal/cli: TestSectionsValidateCleanAfterTheFlip |
| integration/upgrade_store_flip.bats | import: --check, another file, and --replace keep no pre-store copy | internal/store: TestImportCLIReplaceKeepsNoPreStoreCopy |
| integration/upgrade_store_flip.bats | rollback: refuses on an install that never had a legacy file, and leaves its store alone | internal/cli: TestStoreRollbackRefusals |

## Partial coverage left as it is

Each of these bats tests has a Go replacement for its behaviour; what is not
repeated is listed with the reason.

| bats test | not repeated | why |
|---|---|---|
| install_seed.bats #1 "install: a fresh install seeds the store and renders tacquito.yaml from it" | the `chown tacquito:tacquito` call | ownership is set natively now (§3.6, §3.9 item 2); unprivileged tests assert mode and content |
| install_seed.bats #7 "install: a fresh install is fully working" and #8 "the seeded secret is the one 'scope secret lab show' … carry" | the CLI steps after the seed (`config validate`, `user list`, `scope add`, `scope secret lab show`) | the seed, its render, drift and the secret are `internal/lifecycle` tests; the CLI steps on a seeded-like store are the black-box tests of `status_and_scope_lookup.bats`, `user_crud.bats`, `scope_crud.bats`, `scope_prefixes_secret.bats` |
| upgrade_store_flip.bats #2 "flip: afterwards the install is fully working" | the gate run by `upgrade` itself before validate | the gate needs the daemon load-smoke and the unit install, which the CLI sandbox cannot run; `internal/lifecycle: TestFlipAfterwardsTheInstallIsFullyWorking` runs the gate, `internal/cli: TestSectionsValidateCleanAfterTheFlip` the validate after an operator flip |
| upgrade_restart.bats "changes for both backends restart each once" | one upgrade through both real modules | each module's upgrade restarts only its own unit (`internal/backend/tacacs`, `internal/backend/radius` upgrade tests), and the phase order is `internal/lifecycle: TestUpgradeOrderAndSummary`; the real TACACS+ upgrade seams are private to its package |
| upgrade_templates.bats #11 "neither the manifest nor a .new file is a template" | the glob half | resolution looks up `<name>.template` exactly (`internal/devices: TestResolveTemplate`) and the shipped set is embedded, so neither file can be picked |
| model.bats #14, store_import.bats #36, listeners.bats #15/#16/#21, deps.bats #5, go_fetch.bats #2/#5, backend.bats #9/#25, render_radius.bats #46 | see the rows | an in-shell cache, a temp model file, a `source` column, sub-cases of string lookups and some distro-detection inputs have no counterpart in the Go structure; the rows name what is covered |

## Decisions for the user

1. **Self-update trigger (proposed §3.9 item).** The Go `upgrade` rebuilds
   and re-executes whenever the installed binary was not built from HEAD
   (plan §5.2), so a pull or `--branch` switch that changes only
   documentation also rebuilds and re-executes once; 0.1.18 re-executed only
   when `bin/` or `lib/` changed. Deleted bats test: upgrade_restart.bats
   "upgrade --branch to a branch with the same bin/ and lib/ does not
   re-execute" (and the README half of "a pull on the same branch …").
   Pinned now by `internal/lifecycle:
   TestUpgradeAReadmeOnlyPullStillRebuildsBecauseTheBinaryIsNotHEAD`.
   Recommendation: record it under §3.9 item 11.
2. **Output that names `lib/conf.sh`.** `tacctl config defaults` prints
   "generated by conf_emit_defaults() in lib/conf.sh" and `tacctl config
   dump` prints "Defaults: embedded in lib/conf.sh (conf_emit_defaults)"
   (parity with 0.1.18; `characterisation.bats` pins the first). The file no
   longer exists. Recommendation: a §3.9 item changing both to name the
   binary's embedded defaults, decided with WP4.2's documentation work.

## Per-file tables

### tests/unit/conf.bats (62 tests)

The Go file says it is "one Go test per bats test, named after it" (internal/conf/conf_test.go). I checked the bats tests and the Go functions side by side, and they match one-to-one in file order.

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | conf_get: returns default from conf_emit_defaults when no override | internal/conf: TestConfGetReturnsDefaultWhenNoOverride | |
| 2 | conf_get: empty when path missing and no fallback | internal/conf: TestConfGetEmptyWhenPathMissingAndNoFallback | |
| 3 | conf_get: returns fallback when path missing | internal/conf: TestConfGetReturnsFallbackWhenPathMissing | |
| 4 | conf_get: overrides win over defaults | internal/conf: TestConfGetOverridesWinOverDefaults | |
| 5 | conf_get: deep merge keeps sibling defaults when overriding one key | internal/conf: TestConfGetDeepMergeKeepsSiblingDefaults | |
| 6 | conf_get: canonical defaults come from conf_emit_defaults() | internal/conf: TestConfGetCanonicalDefaultsComeFromConfEmitDefaults | |
| 7 | conf_set: creates tacctl.yaml with 0640 perms | internal/conf: TestConfSetCreatesTacctlYamlWith0640Perms | asserts mode 0640 |
| 8 | conf_set: revert-to-default deletes the key (overrides file pruned) | internal/conf: TestConfSetRevertToDefaultDeletesTheKey | |
| 9 | conf_set: coerces integers and booleans | internal/conf: TestConfSetCoercesIntegersAndBooleans | |
| 10 | conf_unset: drops the key + prunes empty parent maps | internal/conf: TestConfUnsetDropsTheKeyAndPrunesEmptyParentMaps | |
| 11 | conf_unset: missing key is a no-op | internal/conf: TestConfUnsetMissingKeyIsANoOp | |
| 12 | conf_set_list + conf_get_list round-trip | internal/conf: TestConfSetListAndGetListRoundTrip | |
| 13 | conf_set_list: lists replace wholesale on override (no concatenation) | internal/conf: TestConfSetListListsReplaceWholesaleOnOverride | Go uses the shipped non-empty default privileges.operator instead of shadowing conf_emit_defaults |
| 14 | conf_set_list: empty input unsets (revert to default) | internal/conf: TestConfSetListEmptyInputUnsets | |
| 15 | conf_get_keys: enumerates the keys of a map | internal/conf: TestConfGetKeysEnumeratesTheKeysOfAMap | |
| 16 | conf_get_keys: empty when path is a scalar / absent | internal/conf: TestConfGetKeysEmptyWhenPathIsAScalarOrAbsent | |
| 17 | conf_set: rejects out-of-range int with clear diagnostic | internal/conf: TestConfSetRejectsOutOfRangeIntWithClearDiagnostic | |
| 18 | conf_set: rejects non-numeric where int required | internal/conf: TestConfSetRejectsNonNumericWhereIntRequired | |
| 19 | conf_set: rejects unknown key as typo | internal/conf: TestConfSetRejectsUnknownKeyAsTypo | |
| 20 | conf_set: rejects ACL name not matching pattern | internal/conf: TestConfSetRejectsACLNameNotMatchingPattern | |
| 21 | aaa.order.<scope>: unset reads empty (render falls back to tacacs-first) | internal/conf: TestAAAOrderUnsetReadsEmpty | |
| 22 | aaa.order.<scope>: round-trip local-first per scope | internal/conf: TestAAAOrderRoundTripLocalFirstPerScope | |
| 23 | aaa.order.<scope>: per-scope overrides are independent | internal/conf: TestAAAOrderPerScopeOverridesAreIndependent | |
| 24 | aaa.order.<scope>: rejects unknown enum value with message naming allowed values | internal/conf: TestAAAOrderRejectsUnknownEnumValue | |
| 25 | aaa.order.<scope>: rejects non-scope path (bare aaa.order) | internal/conf: TestAAAOrderRejectsNonScopePath | |
| 26 | aaa.order.<scope>: setting the implicit default (tacacs-first) prunes override | internal/conf: TestAAAOrderSettingTheImplicitDefaultPrunesOverride | |
| 27 | conf_set_list: rejects malformed CIDRs | internal/conf: TestConfSetListRejectsMalformedCIDRs | |
| 28 | conf_set_list: rejects malformed cisco priv-exec strings | internal/conf: TestConfSetListRejectsMalformedCiscoPrivExecStrings | |
| 29 | conf_set_list: rejects scalar mis-call on list path | internal/conf: TestConfSetListRejectsScalarMisCallOnListPath | |
| 30 | conf_set: rejects list mis-call on scalar path | internal/conf: TestConfSetRejectsListMisCallOnScalarPath | |
| 31 | _conf_validate_overrides_file: no output on a clean file | internal/conf: TestValidateOverridesFileNoOutputOnACleanFile | |
| 32 | _conf_validate_overrides_file: catches hand-edited out-of-range | internal/conf: TestValidateOverridesFileCatchesHandEditedOutOfRange | |
| 33 | _conf_validate_overrides_file: catches hand-edited unknown key | internal/conf: TestValidateOverridesFileCatchesHandEditedUnknownKey | |
| 34 | _conf_validate_overrides_file: catches malformed list elements | internal/conf: TestValidateOverridesFileCatchesMalformedListElements | |
| 35 | _conf_validate_overrides_file: a file that does not parse is one line naming where | internal/conf: TestValidateOverridesFileAFileThatDoesNotParseIsOneLineNamingWhere | |
| 36 | conf_set: an overrides file that does not parse is refused, named, and left as it was | internal/conf: TestConfSetAnOverridesFileThatDoesNotParseIsRefusedNamedAndLeftAsItWas | |
| 37 | conf_unset, conf_set_list, conf_set_json: refused the same way, file untouched | internal/conf: TestConfUnsetSetListSetJSONRefusedTheSameWayFileUntouched | one Go test asserts all three writers (Unset, SetList, SetJSON) |
| 38 | conf_set: an overrides file whose top level is not a mapping is refused | internal/conf: TestConfSetAnOverridesFileWhoseTopLevelIsNotAMappingIsRefused | |
| 39 | conf_set: an empty overrides file is no overrides, and is written | internal/conf: TestConfSetAnEmptyOverridesFileIsNoOverridesAndIsWritten | |
| 40 | conf_get: an overrides file that does not parse reads as the defaults, with one warning on stderr | internal/conf: TestConfGetAnOverridesFileThatDoesNotParseReadsAsTheDefaultsWithOneWarning | |
| 41 | conf_has_override: an overrides file that does not parse has no overrides, and no traceback | internal/conf: TestConfHasOverrideAnOverridesFileThatDoesNotParseHasNoOverrides | |
| 42 | exec_timeout.<scope>: unset reads empty (render falls back to 60) | internal/conf: TestExecTimeoutUnsetReadsEmpty | |
| 43 | exec_timeout.<scope>: round-trip an explicit override | internal/conf: TestExecTimeoutRoundTripAnExplicitOverride | |
| 44 | exec_timeout.<scope>: setting the implicit default (60) prunes override | internal/conf: TestExecTimeoutSettingTheImplicitDefaultPrunesOverride | |
| 45 | exec_timeout.<scope>: rejects below 0 and above 60 | internal/conf: TestExecTimeoutRejectsBelow0AndAbove60 | |
| 46 | exec_timeout.<scope>: rejects non-numeric | internal/conf: TestExecTimeoutRejectsNonNumeric | |
| 47 | tacacs_group.<scope>: unset reads empty (render falls back to TACACS-GROUP) | internal/conf: TestTacacsGroupUnsetReadsEmpty | |
| 48 | tacacs_group.<scope>: round-trip an explicit override | internal/conf: TestTacacsGroupRoundTripAnExplicitOverride | |
| 49 | tacacs_group.<scope>: setting the implicit default prunes override | internal/conf: TestTacacsGroupSettingTheImplicitDefaultPrunesOverride | |
| 50 | tacacs_group.<scope>: rejects invalid characters | internal/conf: TestTacacsGroupRejectsInvalidCharacters | |
| 51 | tacacs_group.<scope>: rejects empty / too-long | internal/conf: TestTacacsGroupRejectsEmptyAndTooLong | |
| 52 | radius_group.<scope>: unset reads empty (render falls back to RADIUS-GROUP) | internal/conf: TestRadiusGroupUnsetReadsEmpty | |
| 53 | radius_group.<scope>: round-trip an explicit override, independent of tacacs_group | internal/conf: TestRadiusGroupRoundTripIndependentOfTacacsGroup | |
| 54 | radius_group.<scope>: setting the implicit default prunes override | internal/conf: TestRadiusGroupSettingTheImplicitDefaultPrunesOverride | |
| 55 | radius_group.<scope>: rejects invalid characters, empty and too-long | internal/conf: TestRadiusGroupRejectsInvalidCharactersEmptyAndTooLong | |
| 56 | scope_mgmt_acl.names.cisco.<scope>: unset reads empty; global/default win | internal/conf: TestScopeMgmtACLNamesCiscoUnsetReadsEmpty | |
| 57 | scope_mgmt_acl.names.<vendor>.<scope>: round-trip override per vendor | internal/conf: TestScopeMgmtACLNamesRoundTripOverridePerVendor | |
| 58 | scope_mgmt_acl.names.<vendor>.<scope>: setting the shipped default prunes override | internal/conf: TestScopeMgmtACLNamesSettingTheShippedDefaultPrunesOverride | |
| 59 | scope_mgmt_acl.names.<vendor>.<scope>: rejects bad ACL name | internal/conf: TestScopeMgmtACLNamesRejectsBadACLName | |
| 60 | scope_mgmt_acl + global mgmt_acl: per-scope write does NOT wipe the global list | internal/conf: TestScopeMgmtACLPerScopeWriteDoesNotWipeTheGlobalList | |
| 61 | scope_auth_method.<scope>: unset reads empty; tacacs and radius both round-trip (no implicit default to prune) | internal/conf: TestScopeAuthMethodTacacsAndRadiusBothRoundTrip | |
| 62 | scope_auth_method.<scope>: only tacacs or radius; a scope name is required | internal/conf: TestScopeAuthMethodOnlyTacacsOrRadiusAScopeNameIsRequired | |

### tests/unit/yaml.bats (37 tests)

The yaml.bats ports are coarser: one Go test often covers several bats tests (internal/model/model_test.go "--- yaml.bats ---" section, legacy_test.go).

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | model_scopes: enumerates every scope by name | internal/model: TestScopesAndExists | ScopeNames() == "dmz lab prod prod-inner" (4 scopes); also TestAccessorListsSorted |
| 2 | model_scope_exists: returns 0 for known scope | internal/model: TestScopesAndExists | Exists("scopes","prod"/"lab") |
| 3 | model_scope_exists: returns non-zero for unknown and empty | internal/model: TestScopesAndExists | "nonexistent", "" -> false |
| 4 | model_scope_prefixes: emits canonical prefixes, longest first | internal/model: TestScopePrefixes | prod; lab /16 before /12 |
| 5 | model_scope_prefixes: unknown scope → empty output | internal/model: TestScopePrefixes | ScopePrefixes("nonexistent") empty |
| 6 | model_scope prefixes: the stored order is the render order, not the display order | internal/model: TestScopePrefixes | get scopes lab prefixes -> /12 then /16; also TestAccessorEntryAndField |
| 7 | model_scope secret: returns raw key for named scope | internal/model: TestScopeSecret | |
| 8 | model_scope secret: unknown scope → empty, and says so with its status | internal/model: TestAccessorMissingEntry | case {"scopes","noscope","secret"} -> "", status 1 |
| 9 | model_prefix_owner: exact match on 10.0.0.0/8 → prod | internal/model: TestPrefixOwner | table case "10.0.0.0/8" |
| 10 | model_prefix_owner: exact match on 10.10.99.0/24 → prod-inner | internal/model: TestPrefixOwner | table case "10.10.99.0/24" |
| 11 | model_prefix_owner: canonicalizes input before comparing | internal/model: TestPrefixOwner | table case "10.10.99.5/24" |
| 12 | model_prefix_owner: no match → empty output | internal/model: TestPrefixOwner | table case "8.8.8.0/24" |
| 13 | model_prefix_owner: a network inside an owned prefix is not owned | internal/model: TestPrefixOwner | table case "10.10.0.0/16" |
| 14 | model_prefix_owner: empty or unparseable input → empty | internal/model: TestPrefixOwner | table cases "" and "not-a-cidr" |
| 15 | model_user scopes: lists scopes for known user in granted order | internal/model: TestUserScopesAndMembers | alice prod,lab; carol lab,dmz |
| 16 | model_user scopes: unknown user → empty, status 1 | internal/model: TestUserScopesAndMembers | nobody -> "", 1 |
| 17 | model_user_exists: known, unknown, empty | internal/model: TestScopesAndExists | users cases alice/nobody/"" |
| 18 | model_scope_users: counts scope membership across users | internal/model: TestUserScopesAndMembers | lab 3, prod 1, dmz 1, prod-inner 0 |
| 19 | model_scope_users: returns member usernames, by name | internal/model: TestUserScopesAndMembers | Members("lab")/("prod") |
| 20 | model_groups: returns the groups defined in the fixture | internal/model: TestGroupPrivLvl | GroupNames() == operator readonly superuser; also TestAccessorListsSorted |
| 21 | model_group_exists: known, unknown, empty | internal/model: TestScopesAndExists | groups cases operator/nosuch/"" |
| 22 | model_group priv_lvl: returns Cisco priv-lvl for built-in groups | internal/model: TestGroupPrivLvl | 1 / 7 / 15 |
| 23 | model_group priv_lvl: unknown group → empty, status 1 | internal/model: TestGroupPrivLvl | nonexistent -> "", 1 |
| 24 | model_user_rows: one line per user with group, status, password date and scopes | internal/model: TestUserRows | exact rows |
| 25 | model_user_info: fields and scope lines; never the hash; status 1 for an unknown user | internal/model: TestUserInfo | |
| 26 | model_user_privlvl: the group's priv-lvl for an active user, nothing otherwise | internal/model: TestUserPrivLvl | includes disabled=true case |
| 27 | model_group_rows: highest priv-lvl first, with user counts | internal/model: TestGroupRows | first assertion |
| 28 | model_group_rows: groups at the same priv-lvl keep the order 'sort -nr' gave them | internal/model: TestGroupRows | second half (alpha/zeta at 7) pins the exact order; the bats re-check against `sort -nr` is not repeated, but the expected order is identical |
| 29 | model_group_info: built-ins first in the shipped order, then the rest by name | internal/model: TestGroupInfo | |
| 30 | model_group_users: every member of a group, the accounting sink included | internal/model: TestGroupUsers | |
| 31 | scope-rows and scope-routing views: scope order follows the routing order | internal/model: TestScopeRowsAndRouting | exact output of both views |
| 32 | views never print a secret or a hash | internal/model: TestViewsNeverPrintSecretsOrHashes | same 15 views |
| 33 | an unknown view is an error, not an empty answer | internal/model: TestUnknownView | |
| 34 | SCOPE_PROTOCOLS matches the store schema's KNOWN_PROTOCOLS | internal/store: TestKnownVendorsAndProtocols | Go has one list (names.KnownProtocols), pinned to "tacacs radius"; the test comment names this bats test |
| 35 | legacy mode: scope readers answer from tacquito.yaml | internal/model: TestLegacyModeScopeReaders | |
| 36 | legacy mode: user and group readers answer from tacquito.yaml | internal/model: TestLegacyModeUserAndGroupReaders | |
| 37 | legacy mode: a user pointing at a missing scope is reported, not hidden | internal/model: TestLegacyModeMissingScope | |

### tests/unit/listeners.bats (23 tests)

The schema half is in internal/conf/listener_test.go, one-to-one and named after the bats tests. The unit-file tests are split between internal/render/tacacs/units_test.go and internal/backend/tacacs/assets_test.go.

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | schema: a listener is stored with only what differs from the defaults | internal/conf: TestListenerSchemaStoredWithOnlyWhatDiffersFromTheDefaults | |
| 2 | schema: the default listener set to its default is not written down | internal/conf: TestListenerSchemaTheDefaultListenerSetToItsDefaultIsNotWrittenDown | |
| 3 | schema: tcp6 takes a bracketed IPv6 address, tcp an IPv4 one, both ':port' | internal/conf: TestListenerSchemaTcp6TakesABracketedIPv6AddressTcpAnIPv4One | |
| 4 | schema: the reserved TLS fields are accepted while tls.enabled is false | internal/conf: TestListenerSchemaTheReservedTLSFieldsAreAcceptedWhileTLSEnabledIsFalse | |
| 5 | schema: tls.enabled: true is refused as reserved, and nothing is written | internal/conf: TestListenerSchemaTLSEnabledTrueIsRefusedAsReservedAndNothingIsWritten | |
| 6 | schema: a hand-written tls.enabled: true is reported by the overrides walk | internal/conf: TestListenerSchemaAHandWrittenTLSEnabledTrueIsReportedByTheOverridesWalk | |
| 7 | schema: bad addresses, networks, roles, names, keys and backends are refused | internal/conf: TestListenerSchemaBadAddressesNetworksRolesNamesKeysAndBackendsAreRefused | |
| 8 | schema: two listeners on one network and address are refused, wildcards included | internal/conf: TestListenerSchemaTwoListenersOnOneNetworkAndAddressAreRefused | |
| 9 | schema: a hand-written collision is reported by the overrides walk | internal/conf: TestListenerSchemaAHandWrittenCollisionIsReportedByTheOverridesWalk | |
| 10 | schema: two listeners may not share a metrics address, except the sink | internal/conf: TestListenerSchemaTwoListenersMayNotShareAMetricsAddressExceptTheSink | |
| 11 | schema: backends.tacacs.level is an integer level; the default is not written down | internal/conf: TestListenerSchemaBackendsTacacsLevelIsAnIntegerLevel | |
| 12 | schema: backends.tacacs.metrics_address is host:port; the default is not written down | internal/conf: TestListenerSchemaBackendsTacacsMetricsAddressIsHostPort | |
| 13 | schema: per-backend settings do not disturb backends.enabled | internal/conf: TestListenerSchemaPerBackendSettingsDoNotDisturbBackendsEnabled | |
| 14 | the shell constants are the python renderer's and the unit's defaults | internal/conf: TestListenerSchemaDefaultsOfTheSettingsAndTheBuiltInListener + internal/render/tacacs: TestUnitsTakeEveryFlagTheDropInSets | split in two: the conf half covers the schema defaults (20, 127.0.0.1:8080) and the built-in listener repr; the unit half covers the four Environment= defaults in tacquito.service and LevelDefault==20. Go has no separate shell and python copies to compare. The sink value (TACACS_METRICS_SINK) is not pinned literally; TestInstanceTemplateNeedsTheRenderedDropIn only checks that the template uses MetricsSink |
| 15 | backend_listeners: the built-in default without a tacctl.yaml | internal/conf: TestBackendListenersTheBuiltInDefaultWithoutATacctlYaml | the Go row omits the bats 6th "source" column (default/override); Go's ListenersEffective has no source field. RADIUS shows "(built-in default)" in its listener display, pinned by internal/backend/radius/listeners_test.go:55 |
| 16 | backend_listeners: the default first, then the others by name, with their source | internal/conf: TestBackendListenersTheDefaultFirstThenTheOthersByName | order and fields pinned; the "override" source column is not checked (same as row 15) |
| 17 | backend_listeners: an invalid hand-written entry is left out, an invalid default falls back | internal/conf: TestBackendListenersAnInvalidHandWrittenEntryIsLeftOutAnInvalidDefaultFallsBack | |
| 18 | validate_listen_address: unchanged verdicts | internal/conf: TestValidateListenAddressUnchangedVerdicts | the same 3 accepted and 5 refused inputs; the "Invalid tcp address" message text is not asserted (the Go comment says the message belongs to the CLI) |
| 19 | units: the template runs the same daemon under the same hardening as tacquito.service | internal/backend/tacacs: TestTemplateRunsTheSameDaemonUnderTheSameHardening | |
| 20 | units: both take every per-listener flag from the environment | internal/render/tacacs: TestUnitsTakeEveryFlagTheDropInSets | the same 5 TACQUITO_* vars, checked in both unit files |
| 21 | units: an instance belongs to tacquito.service and needs its rendered drop-in | internal/render/tacacs: TestInstanceTemplateNeedsTheRenderedDropIn | two small gaps: Go does not check `WantedBy=multi-user.target` in tacquito.service, and checks the no-Alias= rule only in the template, not in tacquito.service |
| 22 | units: the paths tacctl derives for a listener | internal/render/tacacs: TestUnitPaths | includes the production paths |
| 23 | logrotate: one stanza covers every listener's accounting log, restarting once | internal/backend/tacacs: TestLogrotateCoversEveryListener | |

### tests/unit/privilege.bats (12 tests)

Go: `internal/policy` DefaultPrivileges / Privileges (= conf GetList "privileges.<g>") / WritePrivileges (= conf SetList). One coarse Go test (TestPrivileges) covers only the operator group. CLI coverage is the black-box `tests/integration/group_crud.bats` "group privilege ..." tests.

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | default_privileges_for_group: readonly → empty (priv 1 floor) | internal/policy: TestPrivileges | asserts DefaultPrivileges("readonly") is non-nil and empty; also tests/integration/group_crud.bats: "group privilege list: priv-lvl 1 (readonly) has no mappings to emit" |
| 2 | default_privileges_for_group: operator → priv-15 read/diag family | internal/policy: TestPrivileges + internal/conf: TestConfSetListListsReplaceWholesaleOnOverride | TestPrivileges checks len 6, the first item, and Privileges(operator)==DefaultPrivileges(operator); the conf test pins the exact six commands in order via GetList("privileges.operator") |
| 3 | default_privileges_for_group: superuser → empty (priv 15 ceiling) | internal/policy: TestDefaultPrivilegesSuperuserIsEmpty | written in WP4.1. nothing in Go asserts that DefaultPrivileges("superuser") is empty. Low impact: the Cisco renderer skips priv 1 and 15 groups anyway (internal/devices/cisco.go:44) |
| 4 | default_privileges_for_group: unknown group → empty | internal/policy: TestDefaultPrivilegesUnknownGroupIsEmpty | written in WP4.1. nothing in Go asserts that DefaultPrivileges for a custom or unknown group is empty |
| 5 | read_all_privileges: no overrides → only shipped defaults | DROP: bash-only internal no longer exists in Go | read_all_privileges (lib/policy.sh:58) had no callers in the 0.1.18 tree (`git grep` finds only its definition), and Go has no all-groups reader. The shipped default set is pinned by rows 1-2 |
| 6 | read_all_privileges: emits one group\|cmd line per mapping | DROP: bash-only internal no longer exists in Go | same as row 5: an uncalled `group\|cmd` emitter with no Go counterpart |
| 7 | read_group_privileges: filters to one group's commands | internal/policy: TestReadGroupPrivilegesFiltersToOneGroup | written in WP4.1. no Go test writes two groups and reads each back separately, or reads a group with no list (superuser -> ""). Go's Privileges is a plain conf GetList("privileges."+group), so the risk is low |
| 8 | write_group_privileges: creates overrides file when absent | internal/policy: TestPrivileges | starts with no file, writes, then asserts HasOverride("privileges.operator") and reads the list back |
| 9 | write_group_privileges: replaces only the target group's list | internal/policy: TestWriteGroupPrivilegesReplacesOnlyTheTargetGroup | written in WP4.1. no Go or black-box test rewrites one group's privileges and checks that another group's list is left alone |
| 10 | write_group_privileges: empty new_list wipes the target group | tests/integration/group_crud.bats: "group privilege clear: wipes all mappings for a group" | pins the key behaviour: wiping operator, which has a non-empty default, reads back "" (an explicit [], not a revert to defaults), through the Go CLI's WritePrivileges(c, group, nil). The bats check that readonly is left alone is not repeated (see row 9). No Go unit test covers this |
| 11 | write_group_privileges: newline-separated list preserves each item | internal/policy: TestPrivileges | 6 defaults + "" + "show version" are written, and 7 items read back in order (the blank one is dropped); see also internal/conf: TestListItems |
| 12 | write_group_privileges: round-trips through read_group_privileges | internal/policy: TestPrivileges | write then Privileges() read-back |

### tests/unit/deps.bats (5 tests)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | ensure_dependencies: installs nothing when everything is present | internal/lifecycle: TestDepsNothingMissingInstallsNothing | "all present", no apt-get call |
| 2 | ensure_dependencies: installs only what is missing | internal/lifecycle: TestDepsInstallsOnlyWhatIsMissing | exactly one `apt-get install -y -qq podman uidmap` |
| 3 | ensure_dependencies: a missing core package that cannot be installed is fatal | internal/lifecycle: TestDepsMissingCorePackageThatCannotBeInstalledIsFatal | the missing package is wget, not python3-bcrypt, because python3 left DepsCore (plan §3.9 item 6). The "Could not install:" text and the `apt-get update` call are asserted |
| 4 | ensure_dependencies: missing Linux-host packages only warn | internal/lifecycle: TestDepsMissingLinuxHostPackagesOnlyWarn | |
| 5 | linux_image_for_os: maps Ubuntu, derivatives, Debian and the RHEL family; rejects the rest | internal/hosts: TestImageForOS | partial: the Go table covers ubuntu, a derivative (neon), debian, rocky->almalinux:9, ol 8->8, centos 10, fedora->"", and an injected codename->"". It does **not** cover: a derivative whose VERSION_CODENAME differs from UBUNTU_CODENAME (linuxmint wilma/noble, which pins UBUNTU_CODENAME precedence), a quoted debian VERSION_CODENAME, ID="rhel" itself, or the injected VERSION_ID `"9;reboot"` -> "". Reading internal/hosts/platform.go suggests it handles all of these, but no test pins them |

### tests/unit/go_fetch.bats (5 tests)

The Go binary never downloads Go. Plan docs/plans/go-rewrite.md §3.9 item 23: "`tacctl install` no longer downloads, installs or replaces Go: the bootstrap shim installs it". Item 26: the shim fetches from dl.google.com and refuses an unverified tarball. `_go_tarball_fetch` (lib/backends/tacacs.sh) has no Go counterpart, and the same rule lives in the bash shim (bin/tacctl.sh), which the black-box tests/integration/shim.bats covers.

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | _go_tarball_fetch: a tarball matching the published checksum is kept | tests/integration/shim.bats: "shim: without Go, Go 1.26.2 is downloaded, checked and installed, then the binary built" | "Go tarball checksum verified.", both dl.google.com wget URLs; also "shim: a checksum with blanks or a CRLF around it is trimmed and verified" |
| 2 | _go_tarball_fetch: a checksum mismatch removes the tarball and fails | tests/integration/shim.bats: "shim: a Go tarball whose checksum does not match is not installed; Decision 20's way back" | asserts "checksum mismatch!", a failure, nothing installed, and an empty TMPDIR. The bats "Expected:/Got:" lines are not asserted |
| 3 | _go_tarball_fetch: a checksum that cannot be fetched refuses to install | tests/integration/shim.bats: "shim: no checksum to be had: Go is not installed (refused unverified), exit 1" | the message wording is the shim's new one ("was not installed: it could not be verified (no checksum at …)") |
| 4 | _go_tarball_fetch: a checksum URL that answers with a web page refuses to install | tests/integration/shim.bats: "shim: a web page (or anything but 64 lowercase hex digits) where the checksum should be is no checksum: refused" | |
| 5 | _go_tarball_fetch: a failed tarball download is an error | tests/integration/shim.bats: "shim: offline with no Go: it fails loudly on every run and leaves the installed command as it was" | asserts "Could not download https://dl.google.com/go/go1.26.2.linux-amd64.tar.gz." and exit 1, with no Go installed. Not pinned: the offline stub fails every wget, so the bats check that no checksum is fetched after a failed tarball download is not reproduced |

### tests/unit/store.bats (51 tests)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | store: STORE_FILE lives under TACCTL_STATE_DIR | internal/paths: TestResolveOverrides | TACCTL_STATE_DIR=/t/state gives StoreFile /t/state/store.yaml |
| 2 | store: python disabled marker equals DISABLED_MARKER_HEX | internal/store: TestDisabledMarkerIsTheHashPackages | Go has one constant (hash.DisabledMarkerHex), pinned to its value; store refuses it |
| 3 | store_validate: shipped store fixtures are valid | internal/store: TestValidateShippedFixtures | also covers store.radius.yaml |
| 4 | store_validate: missing file fails | internal/store: TestValidateMissingFile | |
| 5 | store_validate: wrong version | internal/store: TestValidateWrongVersion | |
| 6 | store_validate: unknown top-level key and unknown field | internal/store: TestValidateUnknownKeyAndField | |
| 7 | store_validate: built-in groups must exist and be flagged | internal/store: TestValidateBuiltinGroups | |
| 8 | store_validate: group name, priv_lvl range and class characters | internal/store: TestValidateGroupFields | |
| 9 | store_validate: user must reference an existing group and scopes | internal/store: TestValidateUserReferences | |
| 10 | store_validate: reserved user names | internal/store: TestValidateReservedUsers | |
| 11 | store_validate: the sink may not carry a hash or be enabled | internal/store: TestValidateSink | |
| 12 | store_validate: hash must be bcrypt hex and never the marker; value is not echoed | internal/store: TestValidateHash | |
| 13 | store_validate: password_changed must be a real date; unquoted dates are accepted | internal/store: TestValidatePasswordChanged | |
| 14 | store_validate: prefixes must be canonical, non-empty, and owned by one scope | internal/store: TestValidatePrefixes | |
| 15 | store_validate: secret must be a non-empty string; value is not echoed | internal/store: TestValidateSecret | |
| 16 | store_validate: protocols must be known and non-empty | internal/store: TestValidateProtocols | |
| 17 | store_validate: filters must be canonical CIDR lists | internal/store: TestValidateFilters | |
| 18 | store_validate: malformed YAML reports position without quoting the line | internal/store: TestValidateMalformedYAML | |
| 19 | store_init: creates a 0600 store with only the built-in groups | internal/store: TestInit | also pins the bytes |
| 20 | store_init: refuses when a store exists | internal/store: TestInitRefusesExisting | |
| 21 | store writer: an unwritable state directory is a one-line error, not a traceback | internal/store: TestWriterUnwritableDirectory | skipped when run as root |
| 22 | store mutations: refused in legacy mode with the import hint | internal/store: TestMutationsRefusedInLegacyMode | |
| 23 | store writer: file ends up 0600 and no temp files are left behind | internal/store: TestWriterModeAndNoTempFiles | |
| 24 | store writer: a failed validation leaves the store byte-identical | internal/store: TestWriterFailedValidationLeavesStore | |
| 25 | store writer: a no-op mutation does not replace the file | internal/store: TestWriterNoOpKeepsInode | |
| 26 | store writer: snapshot hook runs before a write once backup_snapshot exists | internal/store: TestWriterSnapshotHook | hook is MutateOptions.Snapshot |
| 27 | store writer: a failing snapshot hook blocks the write | internal/store: TestWriterFailingSnapshotBlocks | |
| 28 | store_mutate: custom snippet sees store and args, result is validated | internal/store: TestMutateCustomFunction | python snippet becomes a Go closure; same netops/priv_lvl 99 cases |
| 29 | store_mutate: argument values survive spaces, quotes and equals signs | internal/store: TestMutateValuesSurviveQuoting | |
| 30 | store_user_set: create with hash starts enabled, hash normalised from raw form | internal/store: TestUserSetCreateWithHash | |
| 31 | store_user_set: create without hash starts disabled; group is required | internal/store: TestUserSetCreateWithoutHash | |
| 32 | store_user_set: update touches only the named fields | internal/store: TestUserSetUpdate | "today" uses the env's fixed clock |
| 33 | store_user_set: rejects a bad hash, the marker, and unknown fields without echoing the hash | internal/store: TestUserSetRefusals | |
| 34 | store_user_set: root is created as the accounting sink and takes no password | internal/store: TestUserSetRootIsTheSink | |
| 35 | store_user_set: reserved and malformed names are rejected | internal/store: TestUserSetBadNames | |
| 36 | store_user_del / store_user_rename | internal/store: TestUserDelAndRename | |
| 37 | store_group_set: create, edit, and validation | internal/store: TestGroupSet | |
| 38 | store_group_set: built-ins are editable and keep their flag | internal/store: TestGroupSetBuiltinKeepsFlag | |
| 39 | store_group_del: refuses built-ins, groups in use, and unknown groups | internal/store: TestGroupDel | |
| 40 | store_scope_set: create canonicalises, dedupes and sorts prefixes | internal/store: TestScopeSetCreate | |
| 41 | store_scope_set: a prefix may belong to one scope only | internal/store: TestScopeSetOnePrefixOneScope | |
| 42 | store_scope_set: protocols set and clear | internal/store: TestScopeSetProtocols | |
| 43 | store_scope_del: refuses a referenced scope unless --strip-users | internal/store: TestScopeDel | |
| 44 | store_scope_rename: updates every user's scope list in place | internal/store: TestScopeRename | |
| 45 | store_filters_set: set, canonicalise, clear | internal/store: TestFiltersSet | |
| 46 | store: KNOWN_VENDORS equals SCOPE_VENDORS (lib/scopes.sh) | internal/store: TestKnownVendorsAndProtocols | Go has a single list (names.KnownVendors), pinned to "cisco juniper wti" |
| 47 | store_validate: vendor_attrs must be known vendors, each once; devices a canonical CIDR -> known vendor | internal/store: TestValidateVendorFields | |
| 48 | store_validate: a tagged address must be one scope lookup answers with its own scope | internal/store: TestValidateDeviceOwnership | |
| 49 | store_scope_set: vendor_attrs and devices replace the whole list or mapping, canonical, in a fixed field order; null removes them | internal/store: TestScopeVendorFields | the `model_scope_devices prod` assertion (`cidr\|vendor` in lookup order) is in internal/model: TestVendorViewsAndDevices (same inputs) |
| 50 | model: a scope without vendor fields reads exactly as before they existed | internal/store: TestScopeWithoutVendorFieldsReadsAsBefore | |
| 51 | store_scope_rename and store_scope_del: the vendor fields go with the scope | internal/store: TestVendorFieldsGoWithTheScope | |

### tests/unit/store_import.bats (53 tests)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | import: every tacquito.* fixture imports strictly, validates, and matches its golden model | internal/store: TestImportEveryFixtureMatchesItsGoldenModel | |
| 2 | import: legacy loader and store loader give the same model for every fixture | internal/store: TestImportLegacyAndStoreLoaderAgree | |
| 3 | import: tacquito.minimal / tacquito.multiscope produce the shipped store fixtures | internal/store: TestImportProducesTheStoreFixtures | byte-equal |
| 4 | import: re-importing the same file is a no-op | internal/store: TestImportTwiceIsANoOp | inode kept |
| 5 | import: legacy 'name: exec' service yields the same groups as 'name: shell', with a note | internal/store: TestImportLegacyExecName | |
| 6 | import: edge fixture imports strictly and matches its golden model | internal/store: TestImportEdgeFixture | |
| 7 | import: disabled by marker restores the real hash from the sidecar | internal/store: TestImportDisabledRestoresSidecarHash | |
| 8 | import: marker without a sidecar, and the DISABLED literal, give hash null + disabled | internal/store: TestImportDisabledWithoutSidecar | |
| 9 | import: a sidecar that is not a bcrypt hash blocks a strict import | internal/store: TestImportBadSidecarBlocksStrictImport | |
| 10 | import: root is the accounting sink (no hash, disabled, flagged) | internal/store: TestImportRootIsTheSink | |
| 11 | import: a real hash on root is unrepresentable; --force stores the sink without it | internal/store: TestImportRealHashOnRoot | |
| 12 | import: password dates come from the sidecar files; bad content is noted and ignored | internal/store: TestImportPasswordDates | |
| 13 | import: an unquoted all-digit hash (YAML integer) is read exactly | internal/store: TestImportUnquotedDigitHash | |
| 14 | import: user scope order is kept; a user with no scopes key gets [] and a note | internal/store: TestImportScopeOrderAndMissingScopes | |
| 15 | import: multi-prefix and repeated entries are unioned, canonicalised and sorted | internal/store: TestImportPrefixesUnioned | |
| 16 | import: groups come from users and from unreferenced top-level groups; orphan anchors are noted | internal/store: TestImportGroupsAndOrphanAnchors | |
| 17 | import: prefix_allow / prefix_deny become filters | internal/store: TestImportFilters | |
| 18 | import: unrepresentable content fails, lists every item, writes nothing | internal/store: TestImportUnrepresentableFails | |
| 19 | import: --force drops the unrepresentable items, reports them, and writes a valid store | internal/store: TestImportForceDropsUnrepresentable | |
| 20 | import: legacy read-only mode still serves a file with unrepresentable content | internal/store: TestImportLegacyModeServesUnrepresentable | |
| 21 | import: a user with no group cannot be stored; --force drops the user | internal/store: TestImportUserWithoutGroup | |
| 22 | import: same scope with different keys is refused even with --force, keys not printed | internal/store: TestImportScopeWithTwoKeys | |
| 23 | import: a secret key that YAML reads as a number is refused, not guessed | internal/store: TestImportNumericSecretKey | |
| 24 | import: one prefix in two scopes is refused | internal/store: TestImportPrefixInTwoScopes | |
| 25 | import: a user referencing a scope that does not exist is refused | internal/store: TestImportMissingScope | |
| 26 | import: a missing built-in group is refused | internal/store: TestImportMissingBuiltinGroup | |
| 27 | import: malformed YAML fails with a position and no file content | internal/store: TestImportMalformedYAML | |
| 28 | import: explicit file argument is imported instead of \$CONFIG | internal/store: TestImportExplicitFile | |
| 29 | import: missing source file and bad flags | internal/store: TestImportMissingSource + internal/cli: TestStoreShowAndImportArguments | missing file in the store test; `--bogus` (exit 2) and two files `a b` (exit 2, "Only one file may be given.") in the CLI table |
| 30 | import: refuses to overwrite an existing store without --replace | internal/store: TestImportRefusesToOverwrite | |
| 31 | import: --replace keeps what tacquito.yaml cannot carry | internal/store: TestImportReplaceCarriesOver | |
| 32 | import: --replace snapshots first when backup_snapshot exists | internal/store: TestImportReplaceSnapshotsFirst | |
| 33 | import: the model temp file is cleaned up | internal/store: TestImportLeavesNoTempFiles | Go holds the model in memory; asserts TMPDIR empty after import, --check and a failed --replace |
| 34 | import --check: writes nothing; without a renderer it exits 3 and says so | internal/store: TestImportCheckWithoutRenderer | |
| 35 | import --check: unrepresentable content fails before any render | internal/store: TestImportCheckUnrepresentableBeforeRender | |
| 36 | import --check: the render hook receives the model and an output path; EQUIVALENT passes | internal/store: TestImportCheckEquivalent | hook now receives the *store.Store in memory and returns bytes; the bats check that the temp model JSON file was 0600 has no Go counterpart (no such file exists) |
| 37 | import --check: a non-equivalent render fails with a redacted diff | internal/store: TestImportCheckNotEquivalent | |
| 38 | import --check: render failure and smoke failure both fail the check | internal/store: TestImportCheckRenderAndSmokeFailures | |
| 39 | equiv: a file is equivalent to itself | internal/model: TestEquivSelf | |
| 40 | equiv: comments, anchors-vs-inline and user scope order do not matter | internal/model: TestEquivSpellingDoesNotMatter | first half (variant noalias-reversed) |
| 41 | equiv: one multi-prefix entry equals one entry per prefix in any harmless order | internal/model: TestEquivSpellingDoesNotMatter | second half (minimal-multi vs minimal-split) |
| 42 | equiv: an order change that re-routes clients is NOT equivalent | internal/model: TestEquivReroute | |
| 43 | equiv: the same order change on a scope without users is reported as latent, and still fails | internal/model: TestEquivLatent | |
| 44 | equiv: an entry for a scope without users shadows nothing | internal/model: TestEquivSpareScopeShadowsNothing | |
| 45 | equiv: a user without an accounter inherits its group's, so adding the same one changes nothing | internal/model: TestEquivAccounterInherited | |
| 46 | equiv: prefixes tacquito cannot parse are not treated as the CIDR tacctl would write | internal/model: TestEquivUnparseablePrefixes | first half (bare-address) |
| 47 | equiv: a prefixes block that is not strict JSON yields no provider | internal/model: TestEquivUnparseablePrefixes | second half (trailing-comma) |
| 48 | equiv: scalars compare as the text the daemon decodes, not as YAML types | internal/model: TestEquivScalarsAreText | |
| 49 | equiv: no hash or key is printed, wherever it sits | internal/model: TestEquivNeverPrintsSecrets | first half (secrets-everywhere) |
| 50 | equiv: a changed user hash or group is reported without printing hashes | internal/model: TestEquivNeverPrintsSecrets | second half (changed-hash) |
| 51 | equiv: the 'DISABLED' literal equals the disabled marker; service 'exec' does not equal 'shell' | internal/model: TestEquivDisabledAndExec | |
| 52 | equiv: prefix filters compare as sets | internal/model: TestEquivFiltersAreSets | |
| 53 | import: never produces vendor fields; --replace keeps them, and drops (with --force) a tag the imported prefixes no longer hold | internal/store: TestImportVendorFieldsCarryOver | |

### tests/unit/model.bats (14 tests)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | model_mode: legacy without a store, store with one | internal/model: TestMode | |
| 2 | model_dump: fails cleanly when neither store nor config exists | internal/model: TestLoadNeitherStoreNorConfig | exact "No store at ... and no config at ...." |
| 3 | store loader: each store fixture yields the golden model of its tacquito twin | internal/model: TestModelJSONGoldens | byte-equal to tests/fixtures/model/{minimal,multiscope}.json (plus radius) |
| 4 | store loader: the store wins over tacquito.yaml once it exists | internal/model: TestLoadStoreWinsOverConfig | |
| 5 | store loader: optional fields are filled in with defaults | internal/model: TestOptionalFieldsDefaulted | |
| 6 | store loader: unparseable store fails the read and names the file, not its content | internal/model: TestUnparseableStore | also internal/store: TestLoadUnparseableNamesFileNotContent |
| 7 | legacy loader: reads tacquito.yaml when no store exists | internal/model: TestLegacyLoaderReadsConfig | |
| 8 | legacy loader: reads the multiscope fixture as the pre-store readers did | internal/model: TestLegacyLoaderMultiscopeReaders | same 16 values |
| 9 | legacy loader: reads users added by cmd_add's old layout as the pre-store readers did | internal/model: TestLegacyLoaderOldLayout | |
| 10 | accessors: list forms print sorted names | internal/model: TestAccessorListsSorted | |
| 11 | accessors: entry form prints JSON with the name; field form prints text | internal/model: TestAccessorEntryAndField | |
| 12 | accessors: a missing entry returns 1 and prints nothing | internal/model: TestAccessorMissingEntry | |
| 13 | accessors: an unknown field is an error, not empty output | internal/model: TestAccessorUnknownField | |
| 14 | cache: model_load primes it; a store write invalidates it | internal/model: TestReloadSeesWrites | only the "a write is seen by the next read" half; the stale-cache half ($_TACCTL_MODEL_CACHE set, edit behind its back not seen) is an in-shell global with no Go counterpart (Go loads once per command, no cache) |

### tests/unit/fixtures.bats (11 tests)

WP4.1 kept all eleven: the file moved to `tests/integration/fixtures.bats` (#11 rewritten to read through the CLI), and the tmpenv sandbox guard of `sanity.bats` #2 joined it.

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | load_fixture: tacquito.X.yaml is placed and seeds the store the importer would write | internal/store: TestImportProducesTheStoreFixtures + tests/integration/store_cli.bats: "store import: writes a 0600 store and leaves tacquito.yaml untouched" | the byte pin (plan §1 "Byte-pinned by fixtures.bats:17-41") and 0600 are covered; the helper's seed cache path is not |
| 2 | load_fixture: seeding leaves nothing but store.yaml in the state dir | kept: moved to tests/integration/fixtures.bats (black-box helper test) | helper contract (only store.yaml, no .store.lock / snapshot / pre-store copy left in the state dir) is untested; note the Go import writes backups/legacy/tacquito.yaml.pre-store.<ts> on the flip (TestImportCLIWritesStore), so this would be worth keeping as a black-box test |
| 3 | load_fixture: a second load replaces both the file and the store | kept: moved to tests/integration/fixtures.bats (black-box helper test) | helper replacement (rm + re-seed) untested; importer bytes for minimal covered by internal/store: TestImportProducesTheStoreFixtures |
| 4 | load_fixture: sidecars planted before loading are imported (direct import, not the cache) | kept: moved to tests/integration/fixtures.bats (black-box helper test) | helper's cache bypass and .store.lock removal untested; the importer reading password-date sidecars is internal/store: TestImportPasswordDates |
| 5 | load_fixture: a tacquito.* fixture the importer rejects fails the test and shows why | kept: moved to tests/integration/fixtures.bats (black-box helper test) | helper's rejection report ("rejected tests/fixtures/...") untested; importer refusal is internal/store: TestImportUnrepresentableFails / TestImportCLIStrictThenForce |
| 6 | load_fixture: legacy.*.yaml is placed but not seeded | kept: moved to tests/integration/fixtures.bats (black-box helper test) | pure helper behaviour (legacy.* not seeded); no Go counterpart possible |
| 7 | place_fixture: copies only, no store | kept: moved to tests/integration/fixtures.bats (black-box helper test) | pure helper behaviour; no Go counterpart possible |
| 8 | load_fixture: an unknown fixture fails | kept: moved to tests/integration/fixtures.bats (black-box helper test) | pure helper behaviour; no Go counterpart possible |
| 9 | load_store_fixture: places the store 0600 and leaves tacquito.yaml alone | kept: moved to tests/integration/fixtures.bats (black-box helper test) | pure helper behaviour; no Go counterpart possible |
| 10 | load_store_fixture: an unknown fixture fails | kept: moved to tests/integration/fixtures.bats (black-box helper test) | pure helper behaviour; no Go counterpart possible |
| 11 | load_store_fixture: the library reads the placed store, even after an earlier read | kept, rewritten: tests/integration/fixtures.bats "load_store_fixture: commands read the placed store, also after an earlier one" | pins `_fixture_model_reset` clearing the in-shell model cache of the sourced library; Go has no cross-call cache (one load per command; internal/model: TestReloadSeesWrites) |

### tests/unit/render_radius.bats (47 tests)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | hash: the stored hex becomes the \$2b\$ string crypt(3) takes | internal/render/radius: TestHashRaw | same two hashes, plus `$2y$` and upper-case hex |
| 2 | hash: what is not hex, or decodes to something with a quote or a backslash, is refused | internal/render/radius: TestHashRaw | zz, `"`, `\`, plaintext all refused; message "no bcrypt hash has" |
| 3 | secret: without a backslash it is single-quoted, and only ' is escaped | internal/render/radius: TestFRSecret | identical case table |
| 4 | secret: with a backslash it is double-quoted, backslash and \" escaped | internal/render/radius: TestFRSecret | identical case table |
| 5 | secret: a backslash together with a dollar sign has no safe form and is refused | internal/render/radius: TestFRSecret | `a\b$c`, empty, tab (plus nl, NUL, DEL) |
| 6 | secret: a scope whose secret cannot be written refuses the render, naming the scope and not the secret | internal/render/radius: TestSecretThatCannotBeWrittenRefusesTheRender | the "nothing written" part is pure-render here; backend/radius TestMutationUnwritableSecretIsRefused covers the write side |
| 7 | secret: the same secret in a TACACS+-only scope does not stop the render | internal/render/radius: TestSecretInTacacsOnlyScopeDoesNotStopTheRender | |
| 8 | clients: one per prefix of every scope RADIUS serves, most specific first, with the scope's secret | internal/render/radius: TestClientsPerPrefixMostSpecificFirst | same expected block, byte for byte |
| 9 | clients: a scope whose protocols filter does not name radius has no client and its secret is not in the file | internal/render/radius: TestScopeNotServedHasNoClient | |
| 10 | clients: no scope for RADIUS renders a server without clients | internal/render/radius: TestNoScopeForRadiusRendersServerWithoutClients | |
| 11 | users: one entry per user and served scope, with the hash and the group's reply items | internal/render/radius: TestUsersEntries | bob, alice x3, erin asserted the same way |
| 12 | users: the reply is Service-Type alone; vendor values are check items for the control list, never reply items | internal/render/radius: TestUsersReplyIsServiceTypeAlone | |
| 13 | users: disabled users, the accounting sink and users with only TACACS+ scopes have no entry | internal/render/radius: TestUsersWithoutEntry | |
| 14 | users: a name FreeRADIUS reads as a default for everyone refuses the render | internal/render/radius: TestDefaultNameRefusesTheRender | both halves (served refuses; dave's copy renders) |
| 15 | render id: binds the two files, is stable, and changes with either file's content | internal/render/radius: TestRenderID | |
| 16 | filters: deny and allow become a policy that answers nothing, used for authentication and accounting | internal/render/radius: TestFilters | |
| 17 | filters: none means no policy section and no call of it | internal/render/radius: TestNoFiltersNoPolicy | |
| 18 | vendor clients: every client says its scope, 'generic', and no for every vendor when nothing is enabled | internal/render/radius: TestVendorClientsDefault | |
| 19 | vendor clients: a scope's enabled vendors are yes on its generic clients only | internal/render/radius: TestVendorClientsEnabledOnGenericOnly | |
| 20 | vendor clients: a tagged address is a client of its own, before its prefix, sending its own vendor only | internal/render/radius: TestVendorClientsTaggedAddress | |
| 21 | vendor clients: a tag on a CIDR that is also a prefix of its scope is one client, the tagged one | internal/render/radius: TestVendorClientTagOnPrefixIsOneClient | |
| 22 | vendor clients: the tags of a scope RADIUS does not serve are not rendered | internal/render/radius: TestVendorTagsOfUnservedScopeNotRendered | |
| 23 | vendor policy: each vendor's attribute is added only on a client's exact yes, from the control list, inside the accept path | internal/render/radius: TestVendorPolicy | |
| 24 | auth log: one line per accept and reject names the client's device tag | internal/render/radius: TestAuthLogNamesDeviceTag | |
| 25 | dictionary: the package's main dictionary first, then WTI-Super and tacctl's internal attributes | internal/render/radius: TestDictionary | |
| 26 | render id: changes when the dictionary changes, and the dictionary itself does not carry it | internal/render/radius: TestRenderIDChangesWithTheDictionary | "the dictionary does not carry the id" is asserted in TestRenderID |
| 27 | WTI-Super: the Python bands equal the bash mapping for every privilege level | internal/render/radius: TestWTISuperBands | Go has one implementation, so the Python-vs-bash cross-check is gone; the bands are pinned against 0.1.16's mapping for levels -2..20 |
| 28 | notes: how many scopes send a vendor attribute, and how many addresses are tagged | internal/render/radius: TestNotesOfTheFixture + TestNotesVendorCounts; internal/backend/radius: TestStatusSummaryAndUnsupported + TestStatusVendorLine | vendors\|0\|4\|0 and vendors\|1\|4\|2 notes; status summary text "not sent (no scope enables one" / "enabled for 1 of 4 scope(s), N tagged address(es)" (the Go status test tags 1 address, not 2) |
| 29 | conf: PAP only, own module instances, no proxy, no status server, nothing of the package included | internal/render/radius: TestConfStructure | |
| 30 | conf: command rules are not rendered | internal/render/radius: TestCommandRulesAreNotRendered | |
| 31 | golden: Debian/Ubuntu layout | internal/render/radius: TestGoldenDebian | same goldens (radius.debian.conf/users, radius.dictionary) |
| 32 | golden: RHEL-family layout | internal/render/radius: TestGoldenRHEL | |
| 33 | golden: the two layouts differ in the main settings only | internal/render/radius: TestLayoutsDifferInMainSettingsOnly | |
| 34 | layout: Debian/Ubuntu paths, unit, account and binary | internal/render/radius: TestLayoutDebian; internal/backend/radius: TestDescribe | paths/bin/dict in TestLayoutDebian; units/user via Describe |
| 35 | layout: RHEL-family paths, unit, account and binary | internal/render/radius: TestLayoutRHEL; internal/backend/radius: TestDescribe | |
| 36 | drop-in: Debian runs the daemon in the foreground under the package's unit, RHEL forks; both name tacctl's instance and dictionary | internal/render/radius: TestDropin | TestDropinText also pins the whole Debian text |
| 37 | notes: groups whose command rules restrict something and have RADIUS users are named | internal/render/radius: TestNotesOfTheFixture; internal/backend/radius: TestRenderNotesWarn | "commands\|operator" note; the rendered warning text |
| 38 | notes: a group with a permit-everything rule set is not named | internal/render/radius: TestNotesCommandsOnlyForRestrictingGroupsWithServedUsers | |
| 39 | notes: a secret beyond the interoperability advice is named by scope, never by value | internal/render/radius: TestNotesNameSecretsByScopeNeverByValue + TestNotesOfTheFixture | the "filters\|4 allow, 2 deny" line is in TestNotesOfTheFixture |
| 40 | secret_constraints: the interoperability advice | internal/backend/radius: TestSecretConstraints | also internal/render/radius: TestSecretConstraints (the constants) |
| 41 | describe: no import command (a hand edit cannot be adopted) | internal/backend/radius: TestDescribe | ImportCmd == "", protocol radius, impl freeradius |
| 42 | installed: needs the daemon and something of tacctl's (drop-in or rendered config) | internal/backend/radius: TestInstalled | |
| 43 | device_vars: the ports of the built-in listeners and the scope's secret | internal/backend/radius: TestDeviceVars | |
| 44 | listeners: auth on udp :1812 and acct on udp :1813 without anything written | internal/backend/radius: TestListenersDefault + TestListenersShow | the role and "built-in default" source columns are asserted through Show's text |
| 45 | listeners: the schema takes udp and udp6 for radius, auth or acct, and refuses tcp and 'both' | internal/conf: TestListenerSchemaRadiusTakesUDPAuthOrAcctAndRefusesTCPAndBoth | written in WP4.1. No Go test checks conf's radius listener schema: `SetJSON("listeners.radius.x", …)` refusing tcp ("the radius backend listens on udp or udp6 only"), role "both" ("a radius listener has role acct or auth") or `tls.enabled: true` for radius. internal/conf/listener_test.go covers these rules for tacacs only. The CLI pre-check for tcp is covered (backend/radius TestListenerRefusalsWriteNothing; integration radius.bats "config listen --backend radius: tcp, a taken port…"), and so is a radius `mgmt` udp listener being listed (TestListenersDefault) |
| 46 | listeners: udp and udp6 on one port do not collide; two udp listeners on one port do; tcp 49 is unaffected | internal/render/radius: TestListenersRenderedAsListenSections + TestListenerProblemsRefuseTheRender; internal/conf: TestListenerSchemaTwoListenersOnOneNetworkAndAddressAreRefused | Composite. udp6 `[::]:1812` next to udp :1812 is accepted by SetJSON (helper fails on error); the two-udp collision "already used by listeners.radius.auth" is pinned on a hand-written tacctl.yaml (render time), and at the CLI by backend/radius TestListenerRefusalsWriteNothing; the tcp6 `[::]:49` collision is in conf. No single test runs SetJSON on the two-udp case |
| 47 | listeners: rendered as listen sections, IPv4 wildcard for udp and :: for udp6 | internal/render/radius: TestListenersRenderedAsListenSections | same expected block |

### tests/unit/render_tacacs.bats (37 tests)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | render: store.minimal renders to the golden tacquito.yaml (0640) | internal/render/tacacs: TestRenderMinimalGolden | mode 0640 asserted |
| 2 | render: store.multiscope renders to the golden tacquito.yaml | internal/render/tacacs: TestRenderMultiscopeGolden | |
| 3 | render: a rendered file imports back to the same model and re-renders byte-identically | internal/render/tacacs: TestARenderedFileImportsBackAndReRendersByteIdentically | |
| 4 | render: leaves no temp file behind and replaces the target atomically | internal/render/tacacs: TestRenderLeavesNoTempFileAndReplacesAtomically | |
| 5 | render: secrets are one entry per (scope, prefix), most specific first across scopes | internal/render/tacacs: TestRenderSecretsOnePerScopePrefixMostSpecificFirst | |
| 6 | render: every user carries its own authenticator and the file accounter | internal/render/tacacs: TestRenderEveryUserHasItsAuthenticatorAndTheFileAccounter | |
| 7 | render: disabled users, users without a hash and the root sink get the disabled marker | internal/render/tacacs: TestRenderDisabledUsersAndTheSinkGetTheMarker | |
| 8 | render: a scope limited to another protocol is left out, with its users' references | internal/render/tacacs: TestRenderScopeOfAnotherProtocolIsLeftOut | |
| 9 | render: custom groups follow the built-ins; group services carry priv-lvl and class | internal/render/tacacs: TestRenderCustomGroupsFollowTheBuiltins | |
| 10 | render: command rules come from tacctl.yaml and reach the daemon character for character | internal/render/tacacs: TestRenderCommandRulesReachTheDaemonCharacterForCharacter | |
| 11 | render: prefix filters are emitted sorted, and omitted when empty | internal/render/tacacs: TestRenderPrefixFiltersSortedAndOmittedWhenEmpty | |
| 12 | render: secrets with quotes, backslashes and non-ASCII reach the daemon unchanged | internal/render/tacacs: TestRenderSecretsWithQuotesBackslashesAndNonASCII | |
| 13 | render: names YAML could misread are quoted; names that collide with layout keys get their own key | internal/render/tacacs: TestRenderNamesQuotedAndCollidingGroupKeys | |
| 14 | render: an all-digit hash is quoted so it stays a string | internal/render/tacacs: TestRenderAllDigitHashIsQuoted | |
| 15 | render: an invalid model is refused and nothing is written | internal/render/tacacs: TestRenderInvalidModelIsRefusedAndNothingWritten | |
| 16 | render: a tacctl.yaml that does not parse is refused instead of rendering default command rules | internal/render/tacacs: TestRenderUnparsableTacctlYAMLIsRefused | |
| 17 | render: a command rule with an unknown action is refused | internal/render/tacacs: TestRenderUnknownActionIsRefused | |
| 18 | render: the read-back check catches a file that does not say what the model says | internal/render/tacacs: TestReadbackCatchesAFileThatDoesNotSayWhatTheModelSays (+ TestRenderToFileWritesNothingWhenTheReadbackFails) | The plan lists render_tacacs.bats:300-303 (the `declare -f` sabotage) as a drop. Only the sabotage method is dropped: Go damages the rendered file the same way and asserts the same messages ("does not read back as the model", "scopes differ", no secret) |
| 19 | rendered_check: unrecorded, ok, drift, missing | internal/rendered: TestCheckUnrecordedOKDriftMissing | exit codes 3/0/1/2 and mode 0600 |
| 20 | rendered.json: maps absolute path to sha256; record and forget keep other entries | internal/rendered: TestRecordAndForgetKeepOtherEntries | |
| 21 | rendered_check: a corrupt rendered.json is a failure, never 'ok' | internal/rendered: TestCorruptRecordsAreAFailureNeverOK | code 4 |
| 22 | backends_check_drift: silent before any render; lists drifted and missing artifacts | internal/rendered: TestCheckDriftListsDriftedAndMissing | drift/missing/unreadable lines |
| 23 | tier: config render is superuser-only | internal/tier: TestPermitsMatchesBash | row `config\|render\|0\|0\|1\|1\|0` of testdata/permits.psv (readonly 0, operator 0, superuser 1) |
| 24 | smoke: skipped (2) when the daemon binary is absent | internal/backend/tacacs: TestSmokeSkippedWithoutTheDaemon | |
| 25 | smoke: passes when the daemon serves; runs isolated; the daemon is gone afterwards | internal/backend/tacacs: TestSmokePassesWhenTheDaemonServes + TestSmokeRealDaemonServesAndIsStopped | argv isolation (scripted runner); real process gone afterwards (fake tacquito script) |
| 26 | smoke: a config the daemon rejects fails, with the reason and without its log | internal/backend/tacacs: TestSmokeRealDaemonRejects + TestSmokeNamesTheCause | |
| 27 | smoke: a daemon that never serves fails after the time limit and is killed | internal/backend/tacacs: TestSmokeRealDaemonThatNeverServes | 1s limit, process gone |
| 28 | check: tacquito.minimal raw differs only latently (groups have no command rules yet) | internal/model: TestImportCheckGoldens/minimal.raw | The whole output is compared byte for byte with 0.1.16 bash output (expected/check.minimal.raw.out holds "render: OK", `+ "commands": [`, NOT EQUIVALENT); rc=1; no store written |
| 29 | check: tacquito.legacy-exec raw is NOT equivalent (service 'exec' is not 'shell') | internal/model: TestImportCheckGoldens/legacy-exec.raw | golden has the -exec/+shell lines |
| 30 | check: tacquito.dead-matches raw is NOT equivalent (rendering drops the dead match regexes) | internal/model: TestImportCheckGoldens/dead-matches.raw | |
| 31 | check: tacquito.multiscope raw is NOT equivalent: its users gain command rules | internal/model: TestImportCheckGoldens/multiscope.raw | golden has the prod-inner notes and no "differ only" |
| 32 | check: a fixture with secrets[] in product order is EQUIVALENT once upgrade's migrations have run on it | internal/model: TestImportCheckGoldens/minimal.migrated, /legacy-exec.migrated, /dead-matches.migrated | inputs are testdata/legacy/migrated/*.yaml, the fixtures after 0.1.16's migrations; goldens hold EQUIVALENT, load-smoke SKIPPED, "Check passed. Nothing was written."; rc=0 |
| 33 | check: upgrade's migrations alone leave tacquito.multiscope latently different (prod before prod-inner) | internal/model: TestImportCheckGoldens/multiscope.migrated | rc=1, "differ only in groups without users…" |
| 34 | check: operator command overrides in tacctl.yaml are part of the proof | internal/cli: TestStoreImportCheckOperatorCommandOverridesArePartOfTheProof | written in WP4.1. No Go test runs `store import --check` with a `commands.<group>` override in tacctl.yaml: none checks that the override makes the check fail (`"name": "terminal"` diff) or that it passes again after regenerating tacquito.yaml's commands. The parts are tested separately: the renderer reads overrides (render/tacacs TestRenderCommandRulesReachTheDaemonCharacterForCharacter), and regeneration is in internal/lifecycle TestMigrateRegenerateOneGroupAndTheBlockShapes |
| 35 | check: a rendered file checks EQUIVALENT against itself | internal/model: TestImportCheckGoldens/golden-multiscope | |
| 36 | check: exit 3 only when no renderer is loaded | internal/store: TestImportCheckWithoutRenderer | "render: SKIPPED (no renderer available)", rc 3 |
| 37 | check: the real load-smoke result decides the check | internal/lifecycle: TestFlipALegacyInstallMovesIntoTheStore + TestFlipStopsWhenTheDaemonDoesNotLoadTheRender; internal/store: TestImportCheckRenderAndSmokeFailures | The flip gate runs the real import check with the real LoadSmoke against a fake tacquito (serve → "load-smoke: OK", fatal → "FAILED"); the store test pins how the smoke result maps to the verdict. Black-box: tests/integration/upgrade_store_flip.bats does the same |

### tests/unit/backend.bats (33 tests)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | contract: tacacs and radius are registered, exactly once each, tacacs first | internal/backend/all: TestShippedModulesAreRegisteredTacacsFirst; internal/backend: TestContractTacacsAndRadiusAreRegisteredOnceEachTacacsFirst | ldap and "" not registered; duplicate refused |
| 2 | contract: every registered backend defines every required verb | DROP: bash-specific: source grep / declare -f inspection | plan names backend.bats:37. In Go the Backend interface is checked at compile time; faketest.CheckContract runs every verb on both real modules (internal/backend/tacacs: TestContract, internal/backend/radius: TestContract) |
| 3 | contract: a module defines no backend_<id>_* function that is not a verb | DROP: bash-specific: source grep / declare -f inspection | plan names backend.bats:49 |
| 4 | contract: every module in lib/backends/ is sourced by the entrypoint and registers its file name | DROP: bash-specific: source grep / declare -f inspection | plan names backend.bats:56-59. Registration of the shipped modules: internal/backend/all TestShippedModulesAreRegisteredTacacsFirst |
| 5 | contract: lifecycle phases a module does not know are a no-op, not an error | internal/backend/tacacs: TestContract; internal/backend/radius: TestContract | faketest.CheckContract calls install/upgrade/uninstall with phase "no-such-phase" and fails on an error; also radius TestLifecyclePhasesWithoutWork |
| 6 | contract: install, upgrade and uninstall run the documented phases, in order | internal/backend: TestContractLifecyclePhasesAreTheDocumentedOnes; internal/lifecycle: TestInstallFresh, TestUpgradeOrderAndSummary, TestUninstallYes | The plan lists backend.bats:78 (the `declare -f` helper phases_called) as a drop. The behaviour has a real port: the phase lists, plus the order the commands actually run them in |
| 7 | backend_call: runs the verb with its arguments and returns its status | internal/backend: TestGetReturnsTheBackendAndItsVerbsReturnTheirStatus | |
| 8 | backend_call: an unknown backend or verb is an error (2), not a silent no-op | internal/backend: TestGetAnUnknownBackendOrVerbIsAnError2 | "Unknown backend 'ldap'.", exit 2; an unknown verb exits 2 |
| 9 | backend_describe: one value by key; an unknown key prints nothing and fails | internal/backend/tacacs: TestDescribe | protocol/impl/units/log_dir are asserted. Go's Describe returns a typed struct, so there is no lookup by key and no "unknown key" case |
| 10 | backends_enabled: tacacs by default, with and without a tacctl.yaml | internal/backend: TestEnabledTacacsByDefaultWithAndWithoutATacctlYAML | |
| 11 | backends_enabled: the default needs no read of the merged config | DROP: bash-specific: no-python3-call check | plan names backend.bats:136 |
| 12 | backends_enabled: the shipped default is the schema's default | internal/backend: TestEnabledTheShippedDefaultIsTheSchemasDefault | default and values == registry |
| 13 | backends_enabled: reads backends.enabled, in its order, from tacctl.yaml | internal/backend: TestEnabledReadsBackendsEnabledInItsOrder | includes duplicate collapse |
| 14 | backends_enabled: a backend this tacctl does not have is refused, by name | internal/backend: TestEnabledABackendThisTacctlDoesNotHaveIsRefusedByName | |
| 15 | backends_enabled: follows a tacctl.yaml write in the same shell | internal/backend: TestEnabledFollowsATacctlYAMLWriteInTheSameInvocation | |
| 16 | schema: backends.enabled takes known backends only, non-empty, no duplicates | internal/backend: TestSchemaBackendsEnabledTakesKnownBackendsOnlyNonEmptyNoDuplicates | incl. "requires list input" and no file written |
| 17 | schema: backends.enabled takes whatever the registry holds, so a new module only registers itself | internal/backend: TestSchemaBackendsEnabledTakesWhateverTheRegistryHolds | "(known: tacacs, radius, fake)" |
| 18 | schema: setting backends.enabled to the default writes no override, and is not a shipped default line | internal/backend: TestSchemaSettingBackendsEnabledToTheDefaultWritesNoOverride | |
| 19 | schema: a hand-written backends.enabled is checked by the overrides walk | internal/backend: TestSchemaAHandWrittenBackendsEnabledIsCheckedByTheOverridesWalk | |
| 20 | tacacs artifacts: the rendered tacquito.yaml, then the default listener's drop-in | internal/backend/tacacs: TestArtifacts; internal/backend: TestArtifactsNamesAndOwner | backends_artifacts / backends_artifact_names correspond to Set.Artifacts / ArtifactNames |
| 21 | tacacs artifacts: an install whose hand-managed drop-in is still there has no rendered one | internal/backend/tacacs: TestArtifactsNotConverted | |
| 22 | tacacs installed: needs the daemon binary and the unit file | internal/backend/tacacs: TestInstalled | |
| 23 | tacacs listeners list: the built-in default, then what tacctl.yaml says | internal/backend/tacacs: TestListenersList | The python3-stub half (backend.bats:273) is "bash-specific: no-python3-call check". Go instead checks that a tacctl.yaml naming no listener is not parsed |
| 24 | tacacs listeners list: an install that is not converted shows its hand-managed drop-in | internal/backend/tacacs: TestListenersListNotConverted | |
| 25 | tacacs listeners: list, show, set and reset; 'tacctl config listen' did not grow a 'list' | internal/backend/tacacs: TestListenersShowDefault + TestListenerSetRefusesBadInput | "Current listener: tcp :49"; the `list` case gives "Invalid subcommand: 'list'". The `listeners frobnicate` → exit 2 dispatch has no Go counterpart (Listeners() is a typed interface with no string verb) |
| 26 | tacacs service: restart reports and never fails; other actions pass systemctl through | internal/backend/tacacs: TestServiceRestartReportsAndNeverFails | |
| 27 | tacacs last_login: newest cmd=login of the user in the accounting log, else never | internal/backend/tacacs: TestLastLogin; internal/backend: TestLastLoginTheMostRecentAcrossEnabledBackends | the backends_last_login half is in the second test |
| 28 | backends_last_login: the most recent across enabled backends | internal/backend: TestLastLoginTheMostRecentAcrossEnabledBackends | uses two fake backends instead of tacacs+fake |
| 29 | tacacs secret_constraints and device_vars: no limit, no variables | internal/backend/tacacs: TestSecretConstraintsAndDeviceVars | |
| 30 | tacacs status and log: an unknown part is refused (2) | internal/backend/tacacs: TestUnknownPartsAreRefused | status/log/accounting "nope" → ErrUnsupported, exit 2 |
| 31 | layout: the TACACS+ backend's shipped files are under config/backends/tacacs | DROP: bash-specific: source grep / declare -f inspection | plan names backend.bats:373-384. This checks repo file layout. Note: config/backends/tacacs no longer has tacquito.yaml (it now holds tacquito.service, tacquito@.service, tacquito.logrotate) |
| 32 | layout: no lib file outside the module calls tacquito's unit or its drop-in directly | DROP: bash-specific: source grep / declare -f inspection | plan names backend.bats:373-384 (grep over lib/*.sh) |
| 33 | deps: python3-yaml is a core dependency | DROP: bash-only internal no longer exists in Go (explain) | The Go tool has no python3/PyYAML dependency. internal/lifecycle TestDepsNothingMissingInstallsNothing now pins the opposite: DepsCore == [git, wget] with no python3 |

### tests/unit/sanity.bats (5 tests)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | sanity: tacctl.sh sources without dispatching | internal/paths: TestResolveOverrides + TestResolveDefaults | The derived paths (Config = ETC/tacquito.yaml, AcctLog = LOG/accounting.log, BackupDir = StateDir/backups) are pinned in Go. "Sources without dispatching" is bash-only. BackupDir under an overridden TACCTL_STATE_DIR is asserted only indirectly, by internal/cli TestLifecycleTestsAreSandboxed (hostDefaults) |
| 2 | sanity: tmpenv points at tmpdir, not host | ported: tests/integration/fixtures.bats "tmpenv: every tacctl path points into the test's tmpdir, never at the host" | Self-check of the bats helper, now black-box over every TACCTL_* path. For the Go suite the equivalent guard is internal/cli TestLifecycleTestsAreSandboxed (also internal/lifecycle TestOrchestrationIsSandboxed, internal/backend/radius TestHarnessIsSandboxed) |
| 3 | sanity: core functions are defined after sourcing | DROP: bash-specific: source grep / declare -f inspection | `declare -f cmd_*` |
| 4 | sanity: entrypoint and every lib file pass bash -n | DROP: bash-specific: bash -n / duplicate-function scan (sanity.bats) | |
| 5 | sanity: no function is defined twice across bin/ and lib/ | DROP: bash-specific: bash -n / duplicate-function scan (sanity.bats) | |

### tests/unit/cidr.bats (16 tests)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | validate_cidr: accepts IPv4 networks | internal/cidr: TestValidateAcceptsIPv4 | mapped. Same three inputs |
| 2 | validate_cidr: accepts IPv6 networks | internal/cidr: TestValidateAcceptsIPv6 | mapped |
| 3 | validate_cidr: accepts non-strict host-bits-set forms | internal/cidr: TestValidateAcceptsHostBits | mapped |
| 4 | validate_cidr: rejects garbage | internal/cidr: TestValidateRejectsGarbage | mapped. Same four inputs, and it also checks the message text |
| 5 | canonicalize_cidr: zeros host bits on IPv4 | internal/cidr: TestCanonical | mapped. Map entries 10.1.5.5/24, 172.16.1.99/16 |
| 6 | canonicalize_cidr: lowercases and compresses IPv6 | internal/cidr: TestCanonical | mapped. Entries 2001:DB8::/32, 2001:0db8:0000::/48 |
| 7 | canonicalize_cidr: preserves already-canonical forms | internal/cidr: TestCanonical | mapped. Entries 10.0.0.0/8, 2001:db8::/32 |
| 8 | canonicalize_cidr: invalid input produces empty output | internal/cidr: TestCanonical | mapped. Entries "not-a-cidr", "" |
| 9 | cidr_to_cisco_wildcard: emits 'network wildcard' form for IPv4 | internal/cidr: TestCiscoWildcard | mapped. Same three inputs |
| 10 | cidr_to_cisco_wildcard: returns empty for IPv6 | internal/cidr: TestCiscoWildcard | mapped. Entry 2001:db8::/32 |
| 11 | parse_cidr_list: splits on commas, canonicalizes, dedupes | internal/cidr: TestParseList | mapped. Same input and expected output |
| 12 | parse_cidr_list: empty input → empty output | internal/cidr: TestParseListEmpty | mapped |
| 13 | parse_cidr_list: aborts on invalid entry | internal/cidr: TestParseListInvalid | mapped |
| 14 | sort_cidrs_by_specificity: IPv4 before IPv6 | internal/cidr: TestSortIPv4BeforeIPv6 | mapped |
| 15 | sort_cidrs_by_specificity: supernet before equal-broadcast subnet | internal/cidr: TestSortNarrowerFirstOnEqualNetwork | mapped |
| 16 | sort_cidrs_by_specificity: drops invalid lines silently | internal/cidr: TestSortDropsInvalidSilently | mapped |

### tests/unit/validators.bats (22 tests)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | validate_username: accepts alphanumeric + underscore + hyphen | internal/names: TestValidateUsernameAccepts | mapped. Same inputs |
| 2 | validate_username: rejects whitespace | internal/names: TestValidateUsernameRejects | mapped. Loop case "j smith", with the full message |
| 3 | validate_username: rejects empty | internal/names: TestValidateUsernameRejects | mapped. Loop case "" |
| 4 | validate_username: rejects shell metacharacters | internal/names: TestValidateUsernameRejects | mapped. Loop cases foo;rm, foo$bar, foo/bar, foo.bar |
| 5 | validate_class_name: same rules as username | internal/names: TestValidateClassName | mapped. Same four inputs |
| 6 | validate_regex: accepts valid python regex | internal/names: TestValidateRegex | mapped. Accept loop has `^show .*$` and `config(ure)?` |
| 7 | command_match_is_dead: flags regexes that repeat the command word | internal/names: TestCommandMatchIsDeadFlagsRepeatedCommandWord | mapped. The first four cases are the bats inputs |
| 8 | command_match_is_dead: accepts argument-only regexes | internal/names: TestCommandMatchIsDeadAcceptsArgumentRegexes | mapped. The first five cases are the bats inputs |
| 9 | command_match_is_dead: never flags the catchall or empty input | internal/names: TestCommandMatchIsDeadCatchallAndEmpty | mapped |
| 10 | validate_regex: rejects invalid regex | internal/names: TestValidateRegex | mapped. Reject loop case `(` checks "Invalid regex: '('" |
| 11 | validate_priv_command_string: accepts cisco commands with spaces | internal/names: TestPrivCommandAccepts | mapped |
| 12 | validate_priv_command_string: rejects empty | internal/names: TestPrivCommandRejectsEmpty | mapped |
| 13 | validate_priv_command_string: rejects leading/trailing whitespace | internal/names: TestPrivCommandRejectsEdgeWhitespace | mapped. Loop cases " show", "show " |
| 14 | validate_priv_command_string: rejects shell metacharacters | internal/names: TestPrivCommandRejectsMetacharacters | mapped. Loop cases "show; rm", "show$(pwd)" |
| 15 | validate_priv_command_string: rejects >64 chars | internal/names: TestPrivCommandRejectsOver64 | mapped |
| 16 | validate_command_name: accepts single wildcard | internal/names: TestCommandName | mapped. Accept loop case "*" |
| 17 | validate_command_name: accepts typical verbs | internal/names: TestCommandName | mapped. Accept loop cases show, configure, ping |
| 18 | validate_command_name: rejects digits-first, spaces, wildcard-mixed | internal/names: TestCommandName | mapped. Reject loop cases 1show, "show all", show* |
| 19 | validate_acl_name: accepts letter-start, letters/digits/_/- | internal/names: TestACLName | mapped. VTY-ACL, mgmt_ssh_v2 |
| 20 | validate_acl_name: rejects empty, digit-start, too-long | internal/names: TestACLName | mapped. Covers "", 1-ACL and 64 x A ("too long") |
| 21 | is_disabled_hash: recognizes the hex marker | internal/hash: TestIsDisabled | mapped |
| 22 | is_disabled_hash: rejects real-looking hashes and empty | internal/hash: TestIsDisabled | mapped. Loop cases "", `$2b$12$somehashvalue`, "DISABLED" |

### tests/unit/hash.bats (17 tests)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | BCRYPT_COST: default is 12 when file missing | internal/conf: TestBcryptCostDefaultIs12WhenFileMissing | mapped |
| 2 | BCRYPT_COST: accepts values in [10,14] from overrides | internal/conf: TestBcryptCostAcceptsValuesIn10To14FromOverrides | mapped. 11 and 14 via Set |
| 3 | BCRYPT_COST: clamps out-of-range to default 12 | internal/conf: TestBcryptCostClampsOutOfRangeToDefault12 | mapped. Costs 8 and 99 |
| 4 | BCRYPT_COST: non-numeric value clamps to default | internal/conf: TestBcryptCostNonNumericValueClampsToDefault | mapped |
| 5 | PASSWORD_MIN_LENGTH: default 12, clamps to [8,64] | internal/conf: TestPasswordMinLengthDefault12ClampsTo8To64 | mapped. Same values: 8, 64, 7, 65 |
| 6 | SECRET_MIN_LENGTH: default 16, clamps to [16,128] | internal/conf: TestSecretMinLengthDefault16ClampsTo16To128 | mapped. Same values: 16, 128, 15, 129 |
| 7 | validate_password_strength: accepts 12+ char mixed password | internal/ui: TestStrengthAcceptsMixedPassword | mapped |
| 8 | validate_password_strength: rejects short password | internal/ui: TestStrengthRejectsShort | mapped. Exact message "...minimum is 12." |
| 9 | validate_password_strength: rejects common-weak entries (case-insensitive) | internal/ui: TestStrengthRejectsCommonWeak | mapped. Loop cases Administrator, Qwerty123456, 123456789012 |
| 10 | validate_password_strength: rejects password equal to username | internal/ui: TestStrengthRejectsUsername | mapped |
| 11 | generate_hash: produces hex-encoded bcrypt hash at configured cost | internal/hash: TestGenerateIsHexBcryptAt2bAndCost | mapped. Lower-case hex that decodes to `^$2b$10$`. The bats test's independent python `bcrypt.checkpw` round-trip becomes TestGeneratedHashVerifies (own Verify) and TestGenerateWithVerifiesWithTheLibrary (x/crypto CompareHashAndPassword) |
| 12 | verify_hash: round-trips with generate_hash | internal/hash: TestGeneratedHashVerifies | mapped. Match for the right password, NoMatch for a wrong one. Cost 4 instead of 10 |
| 13 | verify_hash: reports INVALID_HASH on garbage hex | internal/hash: TestVerifyInvalidHash | mapped. Map case "not hex" = "not-hex" |
| 14 | verify_hash: does NOT treat every input as the empty password | internal/hash: TestVerifyDoesNotTreatEveryInputAsEmpty | mapped. Uses a python-generated hash of the empty password. TestGeneratedHashVerifies also checks a Go-generated empty-password hash against "not-empty" |
| 15 | normalize_bcrypt_hash: raw bcrypt → hex | internal/hash: TestNormalizeRawToHex | mapped. Same raw `$2b$10$a...` input |
| 16 | normalize_bcrypt_hash: already-hex stays hex (lowercased) | internal/hash: TestNormalizeHexStaysHexLowercased | mapped. Same hex of `$2b$10$` + 53 dots |
| 17 | normalize_bcrypt_hash: garbage input yields empty output | internal/hash: TestNormalizeRejects | mapped. Loop case "not-a-hash" (returns "", false) |

### tests/integration/backend_mutation.bats (15 tests)

The header of internal/backend/mutation_test.go says it is "Ported from tests/integration/backend_mutation.bats (15 tests)". The fake backend is internal/backend/faketest; the tenv/state/noLeftovers helpers in helpers_test.go mirror the bats helpers.

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | two backends: a mutation renders both, records both, restarts both | internal/backend: TestTwoBackendsAMutationRendersBothRecordsBothRestartsBoth | mapped |
| 2 | two backends: every backend is gated and staged before any is committed | internal/backend: TestTwoBackendsEveryBackendIsGatedAndStagedBeforeAnyIsCommitted | mapped |
| 3 | two backends: only the backend whose artifact changed is restarted | internal/backend: TestTwoBackendsOnlyTheBackendWhoseArtifactChangedIsRestarted | mapped |
| 4 | two backends: a change that alters no artifact restarts nothing | internal/backend: TestTwoBackendsAChangeThatAltersNoArtifactRestartsNothing | mapped |
| 5 | two backends: one gate refusing refuses the command before anything is written | internal/backend: TestTwoBackendsOneGateRefusingRefusesTheCommandBeforeAnythingIsWritten | mapped |
| 6 | two backends: a gate answering 'adopt' forces that backend only | internal/backend: TestTwoBackendsAGateAnsweringAdoptForcesThatBackendOnly | mapped |
| 7 | two backends: a backend that cannot stage leaves the other's artifact and the store untouched | internal/backend: TestTwoBackendsABackendThatCannotStageLeavesTheOthersArtifactAndTheStoreUntouched | mapped |
| 8 | two backends: a commit failing after the other's succeeded puts every artifact, the records and the store back | internal/backend: TestTwoBackendsACommitFailingAfterTheOthersSucceededPutsEveryArtifactTheRecordsAndTheStoreBack | mapped |
| 9 | two backends: a failed first commit removes an artifact that did not exist before | internal/backend: TestTwoBackendsAFailedFirstCommitRemovesAnArtifactThatDidNotExistBefore | mapped |
| 10 | one backend: a commit that fails after replacing tacquito.yaml puts it and its record back | internal/backend: TestOneBackendACommitThatFailsAfterReplacingTacquitoYAMLPutsItAndItsRecordBack | mapped |
| 11 | backends_render_all: --force reaches every backend, --force=<id> one | internal/backend: TestRenderAllForceReachesEveryBackendForceIDOne | mapped |
| 12 | backends_render_all: needs the store, and an enabled list it can resolve | internal/backend: TestRenderAllNeedsTheStoreAndAnEnabledListItCanResolve | mapped |
| 13 | config render: reports each backend, restarts the ones it changed | internal/backend: TestConfigRenderReportsEachBackendRestartsTheOnesItChanged | mapped |
| 14 | drift: an edited artifact of any backend is reported | internal/backend: TestDriftAnEditedArtifactOfAnyBackendIsReported | mapped |
| 15 | backup restore: a backend that cannot stage leaves all files as they were | internal/backend: TestBackupRestoreABackendThatCannotStageLeavesAllFilesAsTheyWere | mapped |

### tests/integration/state_migrate.bats (29 tests)

The header of internal/lifecycle/state_test.go cites this file. Section for section it follows the bats file and has one extra test (TestStateAnItemThatCannotMoveIsReportedAndTheOthersStillMove).

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | state paths: tacctl-owned files live in TACCTL_STATE_DIR, the daemon config stays in TACCTL_ETC | internal/lifecycle: TestStatePathsLiveInTheStateDirTheDaemonConfigStays | mapped. The bats test is the in-shell global check that plan §2.3 cites (state_migrate.bats:50-58). Go ports it over paths.Resolve rather than dropping it |
| 2 | state paths: default state dir is /etc/tacctl | internal/lifecycle: TestStatePathsLiveInTheStateDirTheDaemonConfigStays | mapped. Its last assertion checks the default StateDir of /etc/tacctl. internal/paths TestResolve* also pins it (paths_test.go:52,123) |
| 3 | fresh system: creates a 0700 state dir and links nothing | internal/lifecycle: TestStateFreshSystemCreatesA0700StateDirAndLinksNothing | mapped |
| 4 | fresh system: a missing old directory is not created by the migration | internal/lifecycle: TestStateFreshSystemAMissingOldDirectoryIsNotCreated | mapped |
| 5 | fresh system: tightens a state dir that exists with looser permissions | internal/lifecycle: TestStateFreshSystemTightensALooseStateDir | mapped |
| 6 | legacy system: every item moves and the old path becomes a symlink | internal/lifecycle: TestStateLegacySystemEveryItemMovesAndTheOldPathBecomesASymlink | mapped |
| 7 | legacy system: the daemon config and unknown files stay where they are | internal/lifecycle: TestStateLegacySystemTheDaemonConfigAndUnknownFilesStay | mapped |
| 8 | legacy system: the old paths still read through to the data | internal/lifecycle: TestStateLegacySystemTheOldPathsStillReadThrough | mapped |
| 9 | legacy system: only the items present are moved | internal/lifecycle: TestStateLegacySystemOnlyTheItemsPresentMove | mapped |
| 10 | idempotent: a second run changes nothing and prints nothing | internal/lifecycle: TestStateIdempotentASecondRunChangesAndPrintsNothing | mapped |
| 11 | idempotent: fresh system run twice is stable | internal/lifecycle: TestStateIdempotentAFreshSystemRunTwiceIsStable | mapped |
| 12 | half-migrated: items moved without their symlink get the link back | internal/lifecycle: TestStateHalfMigratedItemsGetTheirLinkBack | mapped |
| 13 | half-migrated: converges to the same state as a clean migration | internal/lifecycle: TestStateHalfMigratedConvergesToTheCleanState | mapped |
| 14 | half-migrated: old data is merged into a state directory that already exists | internal/lifecycle: TestStateHalfMigratedOldDataIsMergedIntoAnExistingStateDir | mapped |
| 15 | rollback: older code writing through the symlink leaves the symlink alone | internal/lifecycle: TestStateRollbackWritingThroughTheSymlinkLeavesItAlone | mapped |
| 16 | rollback: a file replaced by rename is moved over the new one, which is backed up | internal/lifecycle: TestStateRollbackAFileReplacedByRenameWinsAndTheOtherIsKept | mapped |
| 17 | rollback: after healing, a second run is a no-op | internal/lifecycle: TestStateRollbackAfterHealingASecondRunIsANoOp | mapped |
| 18 | rollback: several rounds of rename, migrate keep the newest content and every displaced copy | internal/lifecycle: TestStateRollbackSeveralRoundsKeepTheNewestAndEveryDisplacedCopy | mapped |
| 19 | rollback: an old-path file that is not newer loses; it is kept and the link restored | internal/lifecycle: TestStateRollbackAnOldPathFileThatIsNotNewerLoses | mapped |
| 20 | rollback: an identical regular file is replaced by the link without a backup | internal/lifecycle: TestStateRollbackAnIdenticalFileIsReplacedByTheLinkWithoutABackup | mapped |
| 21 | rollback: a directory recreated at the old path is merged back | internal/lifecycle: TestStateRollbackADirectoryRecreatedAtTheOldPathIsMergedBack | mapped |
| 22 | symlinks: a link to somewhere else is left alone and its target untouched | internal/lifecycle: TestStateSymlinksALinkElsewhereIsLeftAlone | mapped. Checks the "symlink elsewhere; left alone" warning |
| 23 | symlinks: a dangling link at the old path is not followed or replaced | internal/lifecycle: TestStateSymlinksADanglingLinkIsNotFollowedOrReplaced | mapped |
| 24 | symlinks: a link inside an old directory is not followed while merging | internal/lifecycle: TestStateSymlinksALinkInsideAnOldDirectoryMovesAsALink | mapped |
| 25 | symlinks: a symlinked state dir entry is not replaced | internal/lifecycle: TestStateSymlinksASymlinkedStateDirEntryIsNotReplaced | mapped |
| 26 | self-move: state dir equal to the daemon dir is a no-op | internal/lifecycle: TestStateSelfMoveTheDaemonDirAsStateDirIsANoOp | mapped |
| 27 | self-move: state dir reached through a symlink to the daemon dir is a no-op | internal/lifecycle: TestStateSelfMoveThroughASymlinkToTheDaemonDirIsANoOp | mapped |
| 28 | self-move: a state dir nested inside the daemon dir migrates without moving a directory into itself | internal/lifecycle: TestStateSelfMoveANestedStateDirMigratesWithoutMovingIntoItself | mapped |
| 29 | migrated layout: conf_set writes into the state dir and leaves the old path alone | internal/lifecycle: TestStateTheMigratedLayoutWorksWithConfSet | mapped |

### tests/integration/tacquito_patches.bats (6 tests)

The header of internal/backend/tacacs/lifecycle_patches_test.go cites this file. Like the bats file, it uses real git on a throwaway checkout of tests/fixtures/tacquito-src and applies the real patches/*.patch.

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | patches report as not-applied on a pristine tree | internal/backend/tacacs: TestPatchesNotAppliedOnAPristineTree | mapped |
| 2 | apply_tacquito_patches applies the default-permit patch | internal/backend/tacacs: TestPatchesApplyTheDefaultPermitPatch | mapped |
| 3 | apply_tacquito_patches applies the empty accounting server_msg patch | internal/backend/tacacs: TestPatchesApplyTheEmptyAccountingServerMsgPatch | mapped |
| 4 | apply is idempotent: second run does not re-apply | internal/backend/tacacs: TestPatchesApplyIsIdempotent | mapped |
| 5 | tacquito_patches_applied flips with apply / revert | internal/backend/tacacs: TestPatchesAppliedFlipsWithApplyAndRevert | mapped |
| 6 | apply aborts loudly when a patch no longer applies (upstream drift) | internal/backend/tacacs: TestPatchesAbortLoudlyOnUpstreamDrift | mapped. Checks "will not apply cleanly" and exit 1 |

### tests/integration/upgrade_templates.bats (12 tests)

No Go test file cites this bats file, and nothing in the commit messages says it was ported. The Go coverage of templates_sync (internal/lifecycle/templates.go TemplatesSync) is three coarser tests in internal/lifecycle/orchestrate_test.go: TestTemplatesSyncFreshAndManifestGolden, TestTemplatesSyncCustomisedAndRecorded and TestTemplatesSyncHistoryFallback. The black-box tests/integration/upgrade_restart.bats test "a new README, logrotate file, completion or template restarts nothing; a customised template is named in the summary" also covers part of it. Several bats tests are only partly covered.

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | install: the templates are seeded and every one is recorded in the manifest | internal/lifecycle: TestTemplatesSyncFreshAndManifestGolden | mapped. Every template is "Installed:", the manifest equals a sha256sum-format golden, Updated == 7 and nothing is customised |
| 2 | install over a templates directory that is already there keeps a customised template | internal/lifecycle: TestTemplatesSyncHistoryFallback + internal/lifecycle: TestTemplatesInstallOverAnExistingDirectoryKeepsACustomisedTemplate | was PARTIAL, completed in WP4.1 (internal/lifecycle: TestTemplatesInstallOverAnExistingDirectoryKeepsACustomisedTemplate): . Go checks that a pre-manifest customised template is classed as customised. It does not check, for the pre-manifest case, that the content is kept, that `.new` equals the shipped file, that the customised template has no manifest record, or that the unmodified one is recorded |
| 3 | upgrade: a template the operator did not modify follows the release | internal/lifecycle: TestTemplatesSyncCustomisedAndRecorded | mapped. Second half: the file matches its recorded sha and differs from the release, so it is "Updated", the file becomes the shipped one, no `.new` is left and the manifest is re-recorded (equals golden). The black-box upgrade_restart.bats test above also checks "Updated: template: cisco.template" end to end |
| 4 | upgrade: a customised template is kept; the release's version goes beside it as .new, with a warning saying how to compare | internal/lifecycle: TestTemplatesSyncCustomisedAndRecorded + internal/lifecycle: TestTemplatesACustomisedTemplateIsKeptAndAStaleNewIsReplaced | was PARTIAL, completed in WP4.1 (internal/lifecycle: TestTemplatesACustomisedTemplateIsKeptAndAStaleNewIsReplaced): . Covered: content kept, Customised == [cisco.template], Updated == 0, the "Customised template kept" and "Compare: diff" lines, `.new` exists. Not covered: a stale `.new` from an earlier release is replaced, the "This release's version is beside it" line, the manifest record staying unchanged, and resolve_template still returning the customised file with a `.new` present. upgrade_restart.bats (black-box) covers the kept notice and the summary line |
| 5 | upgrade: re-running changes nothing; the only output beyond 'Unchanged' is the still-customised notice | internal/lifecycle: TestTemplatesReRunningChangesNothing | written in WP4.1. Closest is the second sync in TestTemplatesSyncFreshAndManifestGolden, which has no customised template. Untested in Go: re-running with a customised template plus its `.new` rewrites nothing (inode, mtime, size), and the output is only Unchanged lines plus the still-customised notice, printed once |
| 6 | upgrade: a customised template that is brought back to the shipped one is recorded again and its .new goes | internal/lifecycle: TestTemplatesACustomisedTemplateBroughtBackIsRecordedAgain | written in WP4.1. Go removes a `.new` only on the "Updated" branch (TestTemplatesSyncCustomisedAndRecorded). Untested in Go: a file restored to the shipped text (the `mv .new` case, which takes the Unchanged branch) is recorded in the manifest again, its `.new` is deleted, and it then follows the next release |
| 7 | manifest-less: a template that is an older shipped version is refreshed, and the manifest is written | internal/lifecycle: TestTemplatesSyncHistoryFallback + internal/lifecycle: TestTemplatesManifestLessAnOlderShippedVersionIsRefreshed | was PARTIAL, completed in WP4.1 (internal/lifecycle: TestTemplatesManifestLessAnOlderShippedVersionIsRefreshed): . Covered: a pre-manifest file whose content is in the git history is updated (Updated == 6, with `git rev-parse` and `git log` stubbed). Not covered: the manifest is written afterwards (a valid `sha256sum -c` file with every template), with no warning and no `.new` |
| 8 | manifest-less: a customised template is kept, with .new and the warning | internal/lifecycle: TestTemplatesSyncHistoryFallback + internal/lifecycle: TestTemplatesManifestLessACustomisedTemplateIsKept | was PARTIAL, completed in WP4.1 (internal/lifecycle: TestTemplatesManifestLessACustomisedTemplateIsKept): . Covered: the classification (juniper.template customised). Not covered for the manifest-less case: content kept, `.new` written, the warning, and the customised file left unrecorded while the unmodified one is recorded |
| 9 | manifest-less without git history: a template that differs from the shipped one counts as customised | internal/lifecycle: TestTemplatesSyncHistoryFallback | mapped. "Not a clone" part: `git rev-parse` fails, so a file that differs is customised. `.new` and the warning are not asserted there, but the classification is what this test pins |
| 10 | a template that is some other template's shipped content is not taken for a shipped version of its own | internal/lifecycle: TestTemplatesAnotherTemplatesShippedContentIsNotItsOwn | written in WP4.1. No Go test has a template holding another template's shipped content. Go's history check is per path (`git log -- config/templates/<file>`), but nothing pins that juniper's content in cisco.template counts as customised |
| 11 | neither the manifest nor a .new file is a template: resolution and *.template globs skip them | internal/devices: TestResolveTemplate | PARTIAL. Go's ResolveTemplate only stats `<name>.template` and otherwise falls back to the embedded template. TestResolveTemplate covers exact-name override and built-in fallback, but never with a `.new` or `.shipped.sha256` in the directory. The shell-glob half has no counterpart, because Go never globs the state templates directory (assets.TemplateNames lists the embedded files) |
| 12 | uninstall removes the manifest and the .new files with the state directory | DROP: "bash-specific: source grep / declare -f inspection" | The test greps `declare -f cmd_uninstall` for `rm -rf "${TACCTL_STATE_DIR:?}"`. The effect (the state directory, and with it templates/.shipped.sha256 and `*.new`, is removed) is covered by internal/lifecycle: TestUninstallYes, which asserts o.p.StateDir no longer exists |

### tests/integration/backend_cli.bats (deleted tests)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | backend list: every backend with protocol, implementation, installed, enabled, service | tests/integration/backend_cli.bats: "cli: backend list shows both shipped backends, installed and enabled or not" | Same table: header row, the installed+enabled tacacs row, a not-installed row (radius instead of fake). Also internal/cli: TestBackendListStatusAndUsage |
| 2 | backend list: an installed, disabled backend shows its own service state | tests/integration/radius.bats: "disable: stops and disables the unit, removes the drop-in, keeps the rendered files; enable brings it back without installing" | Asserts `radius radius freeradius yes no inactive` once RADIUS is disabled. That pins the backend's own service state, but here it is inactive, not active |
| 3 | backend list: needs no store and does not write anything | tests/integration/backend_cli.bats: "cli: backend list and status write nothing and start nothing" + internal/cli: TestSectionsBackendListNeedsNoStore | was PARTIAL, completed in WP4.1 (internal/cli: TestSectionsBackendListNeedsNoStore): the write-nothing/start-nothing part is kept. Missing: `backend list` with no store.yaml succeeding. No Go or bats test runs it without a store |
| 4 | backend status: per backend, the service and each listener, tcp and udp probed apart | tests/integration/backend_cli.bats: "cli: backend status shows each backend under a heading; one id; an unknown or empty one is refused" + internal/cli: TestSectionsBackendStatusTCPAndUDPListeners | was PARTIAL, completed in WP4.1 (internal/cli: TestSectionsBackendStatusTCPAndUDPListeners): headings, State, Service, the tcp `Listener default` line and `ss -tlnp` are covered. Missing: udp listener lines (`Listener auth/acct: udp :1812/:1813 ... listening`) and the `ss -ulnp` probe. RADIUS is never installed+active under `backend status` in any test (listenerProbe udp path untested) |
| 5 | backend status: one backend by id, a port nobody listens on is named, a missing backend is said | tests/integration/backend_cli.bats: "cli: backend status shows each backend under a heading; one id; an unknown or empty one is refused" | With "cli: backend status names a port nobody listens on" (port 49 not detected). Also internal/cli: TestBackendListStatusAndUsage |
| 6 | backend list and status are read-only commands: they never write or start anything | tests/integration/backend_cli.bats: "cli: backend list and status write nothing and start nothing" + internal/cli: TestSectionsBackendListStatusReadOnlyWithTwo | was PARTIAL, completed in WP4.1 (internal/cli: TestSectionsBackendListStatusReadOnlyWithTwo): only TACACS+ is enabled there. Missing: the check with a second backend enabled and running, where that backend's service must not be started, stopped or restarted. Also tests/integration/tiers.bats "tier: backend list and backend status are read-only commands, for both lower tiers" |
| 7 | backend: no subcommand, or an unknown one, prints the usage and fails | tests/integration/backend_cli.bats: "cli: backend with no subcommand or an unknown one prints the usage, exit 1" | Also internal/cli: TestBackendListStatusAndUsage |
| 8 | backend enable: installs, gates the new backend, renders everything, starts it, in that order | internal/cli: TestBackendEnableOrder | Call order, rendered.Check OK, tacquito not restarted, no leftovers |
| 9 | backend enable: the prompt is shown for an install; no answers 'no' and nothing is touched | internal/cli: TestBackendEnablePromptNo | Includes the empty-stdin case |
| 10 | backend enable: yes at the prompt installs | internal/cli: TestBackendEnablePromptYes | |
| 11 | backend enable: an installed backend is not installed again; it is enabled at boot and restarted onto its new config | internal/cli: TestBackendEnableInstalledIsRestarted | |
| 12 | backend enable: an installed backend whose config did not change is started, not restarted | internal/cli: TestBackendEnableUnchangedIsStarted | |
| 13 | backend enable: already enabled is said, not an error, and changes nothing | internal/cli: TestBackendEnableAlreadyEnabled | |
| 14 | backend enable: an unknown or missing id is refused | internal/cli: TestBackendEnableBadArguments | Also internal/cli: TestBackendEnableDisableCLI (the real registry) |
| 15 | backend enable: refused without a store, before anything is installed | internal/cli: TestBackendEnableWithoutStore | |
| 16 | backend enable: an install step that fails leaves backends.enabled, the store and every artifact as they were | internal/cli: TestBackendEnableInstallStepFails | FAKE_PHASE_FAIL=files → fake.PhaseFail |
| 17 | backend enable: the new backend's gate refuses (exit 3); everything as it was, the install stays | internal/cli: TestBackendEnableGateRefuses | FAKE_GATE=3 → GateRefused |
| 18 | backend enable: a gate that says 'adopt' renders that backend with force | internal/cli: TestBackendEnableGateAdopts | FAKE_GATE=10 → GateAdopt |
| 19 | backend enable: a hand-edited artifact of an enabled backend refuses it (exit 3) before anything is written | internal/cli: TestBackendEnableEnabledBackendEdited | The hand edit becomes the stand-in tacacs gate refusing. The real gate's text "was edited since tacctl rendered it" is checked in internal/backend/tacacs render_test.go |
| 20 | backend enable: a backend that cannot stage its render leaves every artifact and the store untouched | internal/cli: TestBackendEnableStageFails | FAKE_FAIL=stage |
| 21 | backend enable: a commit that fails after damaging its artifact is undone, records and all | internal/cli: TestBackendEnableCommitFails | FAKE_FAIL=commit |
| 22 | backend enable: a start step that fails undoes the enable, the render and the records | internal/cli: TestBackendEnableStartStepFails | FAKE_PHASE_FAIL=start |
| 23 | backend enable: an installed backend that does not report active afterwards is undone | internal/cli: TestBackendEnableNotActiveIsUndone | FAKE_START=failed → StartFails. Includes the retry after the fault is cleared |
| 24 | backend enable: an undo restarts the backends the render had restarted, onto what they had | internal/cli: TestBackendEnableUndoRestartsTheOthers | |
| 25 | backend disable: confirms, takes it out of backends.enabled, stops and disables it, leaves its files | internal/cli: TestBackendDisableConfirms | |
| 26 | backend disable: 'no' at the prompt changes nothing | internal/cli: TestBackendDisablePromptNo | |
| 27 | backend disable: -y skips the prompt | internal/cli: TestBackendDisableYes | |
| 28 | backend disable: the last enabled backend is refused | internal/cli: TestBackendDisableLastIsRefused | |
| 29 | backend disable: tacacs is refused while there is no store, even with another backend enabled | internal/cli: TestBackendDisableTacacsWithoutStore | |
| 30 | backend disable: another backend can be disabled without a store (tacctl.yaml only) | internal/cli: TestBackendDisableLegacyMode | |
| 31 | backend disable: tacacs, when another backend stays, stops and disables tacquito and keeps tacquito.yaml | internal/cli: TestBackendDisableTacacsWhenAnotherStays + internal/backend/tacacs: TestServiceWholeBackendStopAndDisable (+ internal/cli: TestBackendDisableTacacsWhenAnotherStays) | was PARTIAL, completed in WP4.1 (internal/backend/tacacs: TestServiceWholeBackendStopAndDisable (+ internal/cli: TestBackendDisableTacacsWhenAnotherStays)): the Go test runs against the stand-in tacacs, so it checks `service stop`/`service disable` calls and that tacquito.yaml is unchanged. Missing: the real systemctl commands (`systemctl stop tacquito`, `systemctl disable tacquito.service`) for a whole-backend stop/disable |
| 32 | backend disable: not enabled is said, not an error; unknown is refused | internal/cli: TestBackendDisableNotEnabledOrUnknown | |
| 33 | backend disable: the gate covers the backends that stay, not the one going | internal/cli: TestBackendDisableGatesTheRest | The remaining backend's hand edit is modelled as the stand-in tacacs gate refusing |
| 34 | backend disable: a service that will not stop is reported, with what to run; backends.enabled is already updated | internal/cli: TestBackendDisableStopFails | FAKE_STOP_FAIL → StopFails |
| 35 | backend disable then enable: the same files, and the backend serves again | internal/cli: TestBackendDisableThenEnable | |
| 36 | mutations after a disable render only the backends that are enabled | internal/cli: TestBackendDisabledIsNotRendered | Calls StoreApply directly rather than through `store_apply store_user_del`. Black-box equivalent for RADIUS: tests/integration/radius.bats "disable: while disabled its artifacts are not rendered, and the store can change" |
| 37 | store rollback: refused while another backend is enabled, since legacy mode is TACACS+ only | internal/cli: TestStoreRollbackRefusals + internal/cli: TestSectionsStoreRollbackRefusedWithAnotherBackend | was PARTIAL, completed in WP4.1 (internal/cli: TestSectionsStoreRollbackRefusedWithAnotherBackend): exit code and both error lines are checked (radius in place of fake). Missing: that the state is unchanged after this refusal (other cases in that test check it) |
| 38 | tacacs service enable and disable act on every listener's unit | internal/backend/tacacs: TestServiceListenerAddressesItsUnit + internal/backend/tacacs: TestServiceWholeBackendEnableAndDisableReachEveryListener | was PARTIAL, completed in WP4.1 (internal/backend/tacacs: TestServiceWholeBackendEnableAndDisableReachEveryListener): whole-backend `enable` → `systemctl enable tacquito.service tacquito@mgmt.service` is checked. Missing: whole-backend `disable` → `systemctl disable tacquito.service tacquito@mgmt.service`. Go only checks disable of the single listener mgmt |
| 39 | drift: a hand edit of a disabled backend's artifact is not reported; an enabled one's is, with its own hint | internal/backend: TestDriftSelectionsAndHints | Covers DriftAll/DriftOf selections, the fake "discard the edits" hint with no adopt route, and a disabled backend left out of DriftAll. Also TestDriftAnEditedArtifactOfAnyBackendIsReported |
| 40 | drift: tacquito's artifacts keep the hint that adopts a hand edit | internal/backend: TestDriftSelectionsAndHints | The tacquito.yaml line with "keep the edits: 'tacctl store import --replace' then 'tacctl config render --force'" |
| 41 | drift: a recorded file no backend claims is reported whoever is enabled | internal/backend: TestDriftSelectionsAndHints | The unowned recorded file is reported under DriftAll and DriftUnowned, also with fake disabled. In Go the file is removed ("missing"), where bats appended to it ("drift") |
| 42 | status: one backend prints no backend headings | internal/cli: TestStatusOneBackendNoHeadings | |
| 43 | status: each backend gets a labelled section with all its lines; the rest stays general | internal/cli: TestStatusTwoBackendsASectionEachAndTheV6Parity + internal/cli: TestSectionsStatusEachBackendInItsSection | was PARTIAL, completed in WP4.1 (internal/cli: TestSectionsStatusEachBackendInItsSection): covered are both headings, Config backups above the sections, the RADIUS section's own lines after its heading (tests/integration/radius.bats "status: each backend has its section; ...") and general Users/Config backups (cutover "cli: status and log with two enabled backends ..."). Missing: TACACS+ lines (Config: tacquito.yaml, Authentication Stats) inside the tacacs section with no leakage from the other backend, and Security Posture/Password Age after the backend sections |
| 44 | status: a drifted artifact is shown in its backend's section, and not twice | internal/cli: TestSectionsStatusDriftInItsBackendsSectionOnce | written in WP4.1. DRIFT lines in `status` are tested with one backend only (config_render.bats). Placing them per backend section without repeating them (status.go DriftOf/DriftUnowned) is untested |
| 45 | status: an IPv6 listener of any backend triggers the ACL parity check, naming it | internal/cli: TestStatusTwoBackendsASectionEachAndTheV6Parity | radius auth udp6 → "radius listener auth is udp6 but no IPv6 CIDRs" |
| 46 | status: with one backend the IPv6 parity wording is unchanged | internal/cli: TestSectionsStatusOneBackendIPv6ParityWording | written in WP4.1. No Go or bats test asserts "IPv6 ACL parity: MISSING (listener is tcp6 but no IPv6 CIDRs — v4-mapped clients bypass ACLs)". tests/diff/corpus/log.txt has `config listen tcp6 [::]:49 <<< y ;; status`, but only as a parity diff against 0.1.18 |
| 47 | config validate: one backend, the plain lines as always | tests/integration/status_and_scope_lookup.bats: "config validate: after a render the artifact is reported up to date; a stale one is an error" + internal/cli: TestSectionsValidateOneBackendNoBlock | was PARTIAL, completed in WP4.1 (internal/cli: TestSectionsValidateOneBackendNoBlock): `Rendered config: up to date` is checked. Missing: no "Backend " block heading with a single backend |
| 48 | config validate: a block per backend; one backend's drift does not hide the other's state | tests/integration/radius.bats: "drift: a hand edit of either RADIUS file refuses mutations (exit 3) until 'config render --force', which keeps a copy" + internal/cli: TestSectionsValidateABlockPerBackendDrift | was PARTIAL, completed in WP4.1 (internal/cli: TestSectionsValidateABlockPerBackendDrift): covers `config validate` with two backends enabled, failing with the RADIUS file's DRIFT line and its hint. Missing: the "Backend tacacs:"/"Backend fake:" blocks, the clean backend still saying "up to date", the DRIFT line inside the drifted backend's block, and the count "Validation failed with 1 error(s)." |
| 49 | config validate: each backend's own render state is judged | tests/integration/radius.bats: "validate: a missing artifact is reported for radius, and 'config render' puts it back" + internal/cli: TestSectionsValidateEachBackendsRenderState | was PARTIAL, completed in WP4.1 (internal/cli: TestSectionsValidateEachBackendsRenderState): failure and a "Backend radius:" block are checked. Missing: the "<file> is missing — run 'tacctl config render'" line inside that backend's block while the other block says "up to date". The missing-message is checked with one backend only in internal/cli: TestConfigShowAndValidate |
| 50 | config validate: a disabled backend's edited leftovers are not an error | internal/backend: TestDriftSelectionsAndHints + internal/cli: TestSectionsValidateDisabledBackendsLeftovers | was PARTIAL, completed in WP4.1 (internal/cli: TestSectionsValidateDisabledBackendsLeftovers): a disabled backend's drift left out of DriftAll (the selection validate uses with one backend) is covered. Missing: the command check, `config validate` exiting 0 with "Configuration is valid." and no DRIFT line in that state |
| 51 | config validate: a store that cannot be rendered by one backend is that backend's error | tests/integration/status_and_scope_lookup.bats: "config validate: after a render the artifact is reported up to date; a stale one is an error" + internal/cli: TestSectionsValidateUnknownRenderStateIsOutOfDate | was PARTIAL, completed in WP4.1 (internal/cli: TestSectionsValidateUnknownRenderStateIsOutOfDate): "out of date with the store" as an error is checked with one backend. Missing: an unrecognised RenderCheck answer mapped to "out of date" (config_report.go default branch), and the line inside that backend's block when several are enabled |
| 52 | config show: one backend, the lines it always printed | internal/cli: TestConfigShowAndValidate + internal/cli: TestSectionsShowOneBackend | was PARTIAL, completed in WP4.1 (internal/cli: TestSectionsShowOneBackend): `Listening on:` and `Service status:` are checked. Missing: the `Config file:` line and no "Backend:" block with a single backend |
| 53 | config show: the listener's own port is probed, not 49 | internal/cli: TestSectionsShowProbesTheListenersOwnPort | written in WP4.1. The non-default TACACS+ port probed by `config show` (`Listening on: 10.1.0.1:4901` and "port 4901 not detected") is untested. listeners.bats checks the same for `status` only |
| 54 | config show: a block per backend, tcp and udp listeners probed apart | tests/integration/radius.bats: "config show: lists the RADIUS backend's config file and listeners" + internal/cli: TestSectionsShowABlockPerBackend | was PARTIAL, completed in WP4.1 (internal/cli: TestSectionsShowABlockPerBackend): the RADIUS config file and "1812" appear. Missing: the per-backend "Backend:" blocks, the tacacs block's Config file and Listening on, and `Listening on (auth)`/`(acct)` probed over udp |
| 55 | log: one backend, no heading; the arguments pass through | internal/cli: TestLogArgumentsAndHeadings + internal/cli: TestSectionsLogOneBackendNoHeading | was PARTIAL, completed in WP4.1 (internal/cli: TestSectionsLogOneBackendNoHeading): the pass-through is checked (`log tail 7 ...` → `journalctl -u tacquito --no-pager -n 7`, plus cutover `log tail 3 --backend=tacacs`). Missing: no "== Backend" heading with a single enabled backend and no --backend |
| 56 | log tail\|search\|failures\|accounting: every enabled backend, each under a heading | tests/integration/backend_cli.bats: "cli: status and log with two enabled backends: a section each, under its heading" + internal/cli: TestSectionsLogEveryEnabledBackend | was PARTIAL, completed in WP4.1: covered are `log tail` under both headings (with journalctl -n 5), `log accounting 3` under both headings in order (internal/cli: TestLogArgumentsAndHeadings), and each verb per backend with --backend (radius.bats "log: --backend radius ..."). `log search` and `log failures` across every enabled backend: TestSectionsLogEveryEnabledBackend |
| 57 | log --backend: one backend only, anywhere on the line, no heading | tests/integration/backend_cli.bats: "cli: log --backend: unknown or missing id refused; --backend=<id> anywhere; a disabled backend can be read" | With "cli: status and log with two enabled backends ..." (`log tail --backend radius`: no heading, no tacquito journal). Also internal/cli: TestLogArgumentsAndHeadings |
| 58 | log --backend: an unknown id or none is refused; a disabled backend can be read | tests/integration/backend_cli.bats: "cli: log --backend: unknown or missing id refused; --backend=<id> anywhere; a disabled backend can be read" | Also internal/cli: TestLogArgumentsAndHeadings |
| 59 | log clear: every enabled backend, each with its own confirmation, -y passed on | tests/integration/radius.bats: "log clear --backend radius: truncates the three logs after a yes" + internal/cli: TestSectionsLogClearEveryBackend | was PARTIAL, completed in WP4.1 (internal/cli: TestSectionsLogClearEveryBackend): `-y` reaching the backend with --backend is covered (also internal/backend/radius TestLogClear, internal/backend/tacacs TestLogClear). Missing: `log clear` without --backend running for every enabled backend, each with its own confirmation (the "Clear tacquito logs" prompt plus the other backend's) |
| 60 | log with no subcommand prints the usage with --backend | internal/cli: TestLogArgumentsAndHeadings | Case `{"log"}` → "Usage: tacctl log <subcommand> [--backend <id>] [arguments]" |
| 61 | backup restore: a snapshot that enables a backend that is not installed is refused, nothing changed | internal/cli: TestBackupRestoreRefusesBeforeTouchingAnything | Case 20250101_000000_004: enables radius, which is not installed. Live state unchanged |
| 62 | backup restore: the backends a snapshot enables follow it: enabled at boot, or stopped and disabled | internal/cli: TestSectionsBackupRestoreBackendsFollowTheSnapshot | written in WP4.1. No test covers reconcileBackends (internal/cli/backup.go): "Backend 'X' is not enabled by this snapshot: stopping and disabling its service." with stop+disable, "Backend 'X' is enabled by this snapshot." with enable, and every enabled backend restarted after a restore |
| 63 | backup restore: a render that fails in any backend leaves all files as they were | internal/backend: TestBackupRestoreABackendThatCannotStageLeavesAllFilesAsTheyWere | Two backends, fake stage fails under ApplyForced, state unchanged. The command's "could not be rendered from it" message and the all-files-back check are in internal/cli: TestBackupRestoreAWriterThatFailsPutsEveryFileBack (a different failure cause) |
| 64 | uninstall: selects every backend that is present, enabled or not, and not the ones that are absent | internal/backend: TestPresentIsEnabledThenInstalled | Also internal/lifecycle: TestUninstallYes (an installed, disabled RADIUS is uninstalled) and TestUninstallCancel (an absent RADIUS is not listed). Go returns enabled backends first, then installed ones |
| 65 | uninstall: a tacctl.yaml that cannot say what is enabled takes every backend | internal/backend: TestPresentIsEnabledThenInstalled | The `enable("ldap")` case returns every registered backend |
| 66 | uninstall: the present backends are selected before the first phase, and the phases loop over that selection | DROP: bash-specific: source grep / declare -f inspection | The plan names backend_cli.bats:1034. The effect is covered by internal/lifecycle: TestUninstallYes (phases run in order over the present backends, uninstall.go calls Set.Present() once) |

### kept (tag cutover:wp2-4d)

- cli: backend list shows both shipped backends, installed and enabled or not
- cli: backend status shows each backend under a heading; one id; an unknown or empty one is refused
- cli: backend status names a port nobody listens on
- cli: backend list and status write nothing and start nothing
- cli: backend with no subcommand or an unknown one prints the usage, exit 1
- cli: a backends.enabled naming no backend is refused by list, status and log
- cli: status and log with two enabled backends: a section each, under its heading
- cli: log --backend: unknown or missing id refused; --backend=<id> anywhere; a disabled backend can be read
- cli: completion names backends, and the enabled ones

### tests/e2e/install_seed.bats (20 tests)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | install: a fresh install seeds the store and renders tacquito.yaml from it | internal/lifecycle: TestSeedAFreshInstallSeedsTheStoreAndRendersTacquitoYAML | PARTIAL: the `chown tacquito:tacquito .../tacquito.yaml` call is not asserted (Chown is stubbed to a no-op in the lifecycle tenv). Progress lines, secret not printed, modes 700/600/640/600, GENERATED header, no legacy dir/tacctl.yaml, no systemctl are all asserted. |
| 2 | install: the mode and the generated secret are handed to the caller, not printed | internal/lifecycle: TestSeedAFreshInstallSeedsTheStoreAndRendersTacquitoYAML + internal/lifecycle: TestSeedTheGeneratedSecretIsOnNoCommandLine | was PARTIAL, completed in WP4.1 (internal/lifecycle: TestSeedTheGeneratedSecretIsOnNoCommandLine): Mode==SeedFresh, Secret==$SECRET and "not printed" are asserted. "The secret never reaches a command line during install" is not asserted for install (TestSecretsNeverOnArgv in internal/cli covers only user/scope commands). The `openssl rand -hex 16` call no longer exists: Go reads env.Rand. |
| 3 | install: the store holds the built-in groups, the seed users disabled, the root sink, and scope lab | internal/lifecycle: TestSeedTheStoreHoldsTheBuiltinsTheSeedUsersAndScopeLab + internal/lifecycle: TestSeedTheBuiltinGroupsPrivLvl (+ existing TestSeedTheStoreHoldsTheBuiltinsTheSeedUsersAndScopeLab) | was PARTIAL, completed in WP4.1 (internal/lifecycle: TestSeedTheBuiltinGroupsPrivLvl (+ existing TestSeedTheStoreHoldsTheBuiltinsTheSeedUsersAndScopeLab)): priv_lvl values 1/7/15 are not checked (only that they are non-nil and builtin). Juniper classes, users, scopes, prefixes, secret, filters and scope.default are checked. |
| 4 | install: the fixture of the old installer's output still matches the shipped template | internal/lifecycle: TestSeedTheOldInstallersOutputStillMatchesTheShippedTemplate | |
| 5 | install: what the daemon loads is equivalent to what the old template path produced | internal/lifecycle: TestSeedWhatTheDaemonLoadsIsEquivalentToTheOldTemplatePath | the output must be exactly EQUIVALENT, so no "note:" line can appear |
| 6 | install: the seeded store is byte for byte what importing the old installer's file gives | internal/lifecycle: TestSeedTheSeededStoreIsWhatImportingTheOldFileGives | goes through the gate (UpgradeStoreFlip: check + import + render) instead of separate store_import --check / store_import / render calls; same assertions |
| 7 | install: a fresh install is fully working: valid, no drift, mutations allowed | internal/lifecycle: TestSeedAFreshInstallIsFullyWorking | PARTIAL: drift is empty, render check is current, user add works with no "Previous", and the daemon restarts. Not repeated: the `config validate` CLI output ("Store: valid", "Configuration is valid."), `user list`, the "with scopes: lab" message, and `scope add prod` followed by re-validate. |
| 8 | install: the seeded secret is the one 'scope secret lab show' and the rendered config carry | internal/lifecycle: TestSeedTheSecretIsTheOneTheRenderedConfigCarries | PARTIAL: the rendered keys and prefixes are checked. `tacctl scope secret lab show` printing the seeded secret is not checked. |
| 9 | install: a secret that cannot be generated stops the install before anything is written | internal/lifecycle: TestSeedASecretThatCannotBeGeneratedStopsBeforeAnythingIsWritten | |
| 10 | install: an existing store is kept -- no reseed, no new secret | internal/lifecycle: TestSeedAnExistingStoreIsKept | "openssl not called" is covered by Secret=="" (there is no openssl in Go) |
| 11 | install: an existing store whose rendered config is gone gets it back | internal/lifecycle: TestSeedAnExistingStoreWhoseRenderedConfigIsGoneGetsItBack | |
| 12 | install: an existing legacy tacquito.yaml is not overwritten; it goes through the upgrade gate | internal/lifecycle: TestSeedAnExistingLegacyConfigGoesThroughTheUpgradeGate | users are read from the store model, not through `user list` |
| 13 | install: an existing legacy tacquito.yaml the gate stops on is left exactly as it is | internal/lifecycle: TestSeedAnExistingLegacyConfigTheGateStopsOnIsLeftAsItIs | |
| 14 | install_readme: places README.md world-readable under the script's umask | DROP: umask check (Go asserts created modes: test internal/backend/tacacs: TestInstallAccountCreatesTheUserAndDirectories) | the Go test checks README.md is 0644 and has the same bytes as the source |
| 15 | install_readme: fails loudly when the config directory does not exist yet | internal/backend/tacacs: TestInstallAccountReadmeThatCannotBeWrittenWarns | Different trigger: in Go, installAccount runs MkdirAll on Etc just before the copy, so a missing directory cannot happen. The failure path (copy fails, "Could not install .../README.md." warning) is pinned with README.md as a directory. This matches bash's caller (`install_readme ... \|\| warn`). |
| 16 | install_readme: a checkout without README.md is not an error | internal/backend/tacacs: TestInstallAccountWithoutReadmeIsNotAnError | written in WP4.1. installReadme returns nil when `<tree>/README.md` is not a regular file, but no Go test runs the account phase on a tree without README.md |
| 17 | cmd_install places README.md after the config directory exists | DROP: bash-specific: source grep / declare -f inspection | The effect is covered by internal/lifecycle: TestInstallFresh (the account phase runs before the seed) and internal/backend/tacacs: TestInstallAccountCreatesTheUserAndDirectories (Etc removed, account phase recreates it and places README.md). |
| 18 | uninstall_remove_access: removes both sudoers drop-ins and the Linux host data | internal/lifecycle: TestUninstallRemovesAccess | Plus TestUninstallYes, which checks that SudoersFile, TierSudoersFile, LinuxDir and its parent are gone. TestUninstallRemovesAccess checks that another sudoers.d file is kept. The bats `assert_output ""` no longer applies: uninstall prints its own progress line. |
| 19 | uninstall_remove_access: nothing to remove is not an error; a shared parent directory is kept | internal/lifecycle: TestUninstallRemovesAccess | The second half covers no sudoers files, exit 0, LinuxDir removed and a shared parent kept. The fully empty case (LinuxDir absent too) is not run separately. |
| 20 | cmd_uninstall removes the tier sudoers rules, bash completion and Linux host data | DROP: bash-specific: source grep / declare -f inspection | The effect is covered by internal/lifecycle: TestUninstallYes (TierSudoersFile, Completion, LinuxDir and its parent gone, all through sandboxed path variables). |

### tests/integration/upgrade_store_flip.bats (34 tests)

Shared note: bats `assert_stopped` also ran `user add zed`, expecting "store not initialised". Go's `assertStopped` checks the same state (no store, no render record, no pre-store copy, file unchanged, no systemctl) but does not run the mutation. Legacy-mode refusal is pinned by internal/cli: TestStoreRollbackRestoresThePreStoreFileAndRestarts.

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | flip: a legacy install moves into the store; the old file is kept; the config is rendered and recorded | internal/lifecycle: TestFlipALegacyInstallMovesIntoTheStore | |
| 2 | flip: afterwards the install is fully working: validate is clean, nothing drifted, mutations apply | internal/lifecycle: TestFlipAfterwardsTheInstallIsFullyWorking + internal/cli: TestSectionsValidateCleanAfterTheFlip | was PARTIAL, completed in WP4.1 (internal/cli: TestSectionsValidateCleanAfterTheFlip): drift is empty, user add applies (name: alice), no "Previous", and the daemon restarts. Not repeated: the `config validate` CLI run ("Rendered config: up to date", no "not initialised"), and the upgrade 'files' phase (unit install and keep/discard) before the gate. |
| 3 | flip: the gate judges the file as upgrade's legacy migrations leave it | internal/lifecycle: TestFlipTheGateJudgesTheFileAsTheMigrationsLeaveIt | the unmigrated file fails the gate itself (stopped, "the check above did not pass") instead of `store_import --check` exit 1 |
| 4 | stop: content the store cannot represent -- nothing is forced, nothing changes | internal/lifecycle: TestFlipStopsOnContentTheStoreCannotRepresent | reads are checked via model.Load in legacy mode (mallory) instead of `user list` |
| 5 | stop: a clean import that is not equivalent (secrets out of specificity order) is not sorted to make it pass | internal/lifecycle: TestFlipStopsOnACleanImportThatIsNotEquivalent | |
| 6 | stop: the daemon does not load the rendered config | internal/lifecycle: TestFlipStopsWhenTheDaemonDoesNotLoadTheRender | |
| 7 | stop: without the daemon binary the load-smoke cannot run, and a skipped smoke is not a pass | internal/lifecycle: TestFlipStopsWithoutTheDaemonBinary | "the check alone calls a skipped smoke a pass" is covered by internal/store: TestImportCheckRenderAndSmokeFailures (ErrSmokeSkipped gives rc 0 and "daemon load-smoke:   SKIPPED") |
| 8 | stop: 'clean import, equivalence not proven' (check exit 3) is not a pass | internal/lifecycle: TestFlipStopsWhenEquivalenceIsNotProven | |
| 9 | stop: no tacquito.yaml at all | internal/lifecycle: TestFlipStopsWithoutATacquitoYAML | |
| 10 | stop: a render that fails after the import takes the store away again | internal/lifecycle: TestFlipARenderThatFailsTakesTheStoreAwayAgain | |
| 11 | re-run: a store that exists is never re-imported or overwritten | internal/lifecycle: TestFlipAStoreThatExistsIsNeverReimported | CONFIG_SYNC_RENDERED==0 corresponds to upgradeSync() returning false |
| 12 | re-run: a second upgrade after a flip changes nothing | internal/lifecycle: TestFlipASecondUpgradeAfterAFlipChangesNothing | |
| 13 | re-run: a stopped upgrade stops the same way again, and passes once the cause is gone | internal/lifecycle: TestFlipAStoppedUpgradeStopsAgainAndPassesOnceTheCauseIsGone | |
| 14 | re-run: an upgrade interrupted between writing the store and rendering is finished by the next one | internal/lifecycle: TestFlipAnInterruptedUpgradeIsFinishedByTheNextOne | |
| 15 | re-run: the first sync that renders asks for a restart; the gate's caller sees it | internal/lifecycle: TestFlipAnInterruptedUpgradeIsFinishedByTheNextOne | covered inline ("The first sync that renders asks for a restart; the next does not") |
| 16 | legacy: a migration that changes tacquito.yaml asks for a restart; a second run does not | internal/lifecycle: TestFlipALegacyMigrationThatChangesTheFileAsksForARestart | |
| 17 | legacy: the exec service-name migration alone asks for a restart too | internal/lifecycle: TestFlipTheExecServiceNameMigrationAloneAsksForARestart | |
| 18 | re-run: a store beside a never-rendered config that says something else leaves that config alone | internal/lifecycle: TestFlipAStoreBesideADifferentNeverRenderedConfigLeavesItAlone | |
| 19 | re-run: a store beside a never-rendered, equivalent config is not adopted while the daemon cannot load the render | internal/lifecycle: TestFlipAnEquivalentNeverRenderedConfigIsNotAdoptedWhileTheDaemonCannotLoadIt | |
| 20 | re-run: with a store, a hand-edited rendered config is reported and left alone | internal/lifecycle: TestFlipAHandEditedRenderedConfigIsReportedAndLeftAlone | |
| 21 | rollback: restores the pre-store file, removes the store and the render record, restarts | internal/cli: TestStoreRollbackRestoresThePreStoreFileAndRestarts | the flipped state is made by `store import` + `config render --force` instead of the upgrade gate (same end state) |
| 22 | rollback: the next upgrade flips again and reuses the pre-store copy | internal/cli: TestStoreRollbackThenImportAgainAndRollBackAgain + internal/lifecycle: TestFlipAfterARollbackTheNextUpgradeFlipsAgainReusingThePreStoreCopy | was PARTIAL, completed in WP4.1 (internal/lifecycle: TestFlipAfterARollbackTheNextUpgradeFlipsAgainReusingThePreStoreCopy): after a rollback, a second `store import` reuses the single pre-store copy. The upgrade gate (UpgradeStoreFlip) is not run after a rollback, so "the next upgrade flips again" is not pinned directly. |
| 23 | rollback: anything but 'y' at the prompt changes nothing | internal/cli: TestStoreRollbackAnythingButYChangesNothing | |
| 24 | rollback: says so when the store changed since the import; the change survives in the snapshot | internal/cli: TestStoreRollbackWarnsWhenTheStoreChangedSinceTheImport | |
| 25 | rollback: an unchanged store draws no such warning | internal/cli: TestStoreRollbackRestoresThePreStoreFileAndRestarts | asserted inline ("an unchanged store drew the warning"), with answer y instead of n |
| 26 | rollback: a hand-edited rendered config is kept under backups/legacy first | internal/cli: TestStoreRollbackKeepsAHandEditedRenderedConfigFirst | |
| 27 | rollback: refuses when there is no store | internal/cli: TestStoreRollbackRefusals | first case |
| 28 | rollback: refuses on an install that never had a legacy file, and leaves its store alone | internal/cli: TestStoreRollbackRefusals + internal/cli: TestStoreRollbackRefusals | was PARTIAL, completed in WP4.1 (internal/cli: TestStoreRollbackRefusals): (second case): the store is a sandbox store plus render, not install_seed. The store sha, both error lines and no systemctl are checked. Not checked: tacquito.yaml unchanged and rendered.json still present. |
| 29 | rollback: refuses a pre-store file that cannot be read as a config | internal/cli: TestStoreRollbackRefusals | fourth case |
| 30 | rollback: ignores a symlink and takes the newest pre-store file | internal/cli: TestStoreRollbackTakesTheNewestRegularPreStoreFile | also internal/store: TestPreStoreLatest |
| 31 | rollback: takes no arguments | internal/cli: TestStoreRollbackRefusals | "Arguments: usage, exit 2" case, store kept |
| 32 | rollback: superuser only | internal/cli: TestStoreRollbackIsSuperuserOnly | |
| 33 | import: the first import of the live config keeps it, so a manual import can be rolled back too | internal/cli: TestStoreRollbackRestoresThePreStoreFileAndRestarts | flippedSandbox runs `store import` (asserts "Pre-store ... kept as ...pre-store."), then `config render --force`, then exactly one pre-store file. The rollback restores the original sha. The "only one file in backups/legacy after render --force" part (no drift copy) is pinned by tests/integration/config_render.bats: "config render: refuses to replace a file tacctl never rendered; --force saves it first". Pre-store bytes and mode: internal/store: TestImportCLIWritesStore. |
| 34 | import: --check, another file, and --replace keep no pre-store copy | internal/store: TestImportCLICheckNothingWritten + internal/store: TestImportCLIReplaceKeepsNoPreStoreCopy | was PARTIAL, completed in WP4.1 (internal/store: TestImportCLIReplaceKeepsNoPreStoreCopy): --check (tree unchanged) is covered here, and a named file is covered by internal/store: TestImportCLINamedFile (no legacy dir). --replace of an existing store keeping no pre-store copy is not tested in Go: every --replace test runs a first import that already made one. |

### tests/integration/migrate_dead_command_matches.bats (10 tests)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | scrape: a stale tacquito.yaml block with dead regexes is NOT written as an override | internal/lifecycle: TestMigrateScrapeAStaleBlockWithDeadRegexesIsNotAnOverride | |
| 2 | scrape: a genuinely customized block keeps its non-dead rules as an override | internal/lifecycle: TestMigrateScrapeACustomizedBlockKeepsItsRulesAsAnOverride | |
| 3 | heal: an override equal to the default once dead regexes are dropped is removed | internal/lifecycle: TestMigrateHealAnOverrideEqualToTheDefaultIsDropped | |
| 4 | heal: a customized override keeps its rules but loses the dead regexes | internal/lifecycle: TestMigrateHealACustomizedOverrideLosesOnlyTheDeadRegexes | |
| 5 | heal: no-op when overrides carry no dead regexes | internal/lifecycle: TestMigrateHealIsANoOpWithoutDeadRegexes | |
| 6 | end to end: scrape + heal + regenerate leaves show as a name-only permit in tacquito.yaml | internal/lifecycle: TestMigrateEndToEndShowIsANameOnlyPermitInTacquitoYAML | |
| 7 | with a store: the scrape ingests nothing from the rendered file | internal/lifecycle: TestMigrateWithAStoreTheScrapeIngestsNothing | |
| 8 | with a store: heal + regenerate re-renders tacquito.yaml from tacctl.yaml | internal/lifecycle: TestMigrateWithAStoreHealAndRegenerateReRender | "config render: already up to date" goes through Set.ConfigRender instead of the CLI |
| 9 | with a store: regenerate does not overwrite a hand-edited file, and does not fail the upgrade | internal/lifecycle: TestMigrateWithAStoreRegenerateLeavesAHandEditedFileAlone | |
| 10 | config validate: flags a hand-edited override whose match regex can never fire | internal/lifecycle: TestMigrateConfigValidateFlagsADeadRegexOverride + internal/cli: TestSectionsValidateDeadRegexOverride | was PARTIAL, completed in WP4.1 (internal/cli: TestSectionsValidateDeadRegexOverride): Schema.ValidateFile reporting "commands.operator ... can never match" is pinned. `tacctl config validate` exiting non-zero on it (the CLI wiring in config_report.go) is not. No Go or remaining bats test runs config validate against a schema-invalid tacctl.yaml override. |

### tests/integration/migrate_exec_service_name.bats (7 tests)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | migrate exec->shell: rewrites all three Cisco exec service anchors | internal/lifecycle: TestMigrateExecRewritesAllThreeCiscoAnchors | |
| 2 | migrate exec->shell: leaves junos-exec services untouched | internal/lifecycle: TestMigrateExecRewritesAllThreeCiscoAnchors | junos-exec count == 3 asserted inline |
| 3 | migrate exec->shell: preserves each anchor's priv-lvl values | internal/lifecycle: TestMigrateExecRewritesAllThreeCiscoAnchors | exec_operator [7] and exec_superuser [15] asserted inline |
| 4 | migrate exec->shell: snapshots the pre-migration config | internal/lifecycle: TestMigrateExecBacksUpThePreMigrationConfig | |
| 5 | migrate exec->shell: second run is an idempotent no-op | internal/lifecycle: TestMigrateExecASecondRunIsANoOp | |
| 6 | migrate exec->shell: no-op on an already-current (name: shell) config | internal/lifecycle: TestMigrateExecNoOpOnACurrentConfig | |
| 7 | migrate exec->shell: with a store the file is left alone; the import and render do the healing | internal/lifecycle: TestMigrateExecWithAStoreTheFileIsLeftAlone + internal/lifecycle: TestMigrateExecWithAStoreTheRenderKeepsTheOperatorPrivLvl (+ existing TestMigrateExecWithAStoreTheFileIsLeftAlone) | was PARTIAL, completed in WP4.1 (internal/lifecycle: TestMigrateExecWithAStoreTheRenderKeepsTheOperatorPrivLvl (+ existing TestMigrateExecWithAStoreTheFileIsLeftAlone)): after `config render --force`, "exec_operator keeps values: [7]" is not asserted (shell count 3 and exec count 0 are) |

### tests/integration/units_convert.bats (35 deleted tests)

All in `internal/backend/tacacs` (lifecycle_units_test.go unless a file is named). The Go tests port the bats bodies almost line for line.

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | install: a fresh machine gets the unit, the template and the default listener's drop-in | internal/backend/tacacs: TestUnitsInstallFresh | |
| 2 | install: the first run reports 'changed' and keeps copies until the caller has restarted | internal/backend/tacacs: TestUnitsInstallFirstRunReportsChanged | |
| 3 | convert: the drop-in's custom values move into tacctl.yaml and the unit sees the same flags | internal/backend/tacacs: TestUnitsConvertMovesTheDropInIntoTacctlYAML | readers are called through the backend API (show, LogLevel, Metrics), not the CLI |
| 4 | convert: only what the drop-in set is written (a log level alone, as on the dev server) | internal/backend/tacacs: TestUnitsConvertWritesOnlyWhatTheDropInSet | |
| 5 | convert: an install without a drop-in just gets the new files | internal/backend/tacacs: TestUnitsConvertWithoutADropIn | |
| 6 | convert: the drop-in is the truth while it exists; values tacctl.yaml held for those keys give way | internal/backend/tacacs: TestUnitsConvertDropInIsTheTruth | |
| 7 | convert: needs no store (an install still in legacy mode converts too) | internal/backend/tacacs: TestUnitsConvertNeedsNoStore | |
| 8 | convert: unquoted and multi-assignment Environment= lines are read as systemd reads them | internal/backend/tacacs: TestUnitsConvertReadsEnvironmentAsSystemdDoes | |
| 9 | convert: literal flags of a unit from before the drop-in are kept | internal/backend/tacacs: TestUnitsConvertKeepsLiteralFlags | |
| 10 | convert: the daemon is not touched; only systemd's view of the files is reloaded | internal/backend/tacacs: TestUnitsConvertDoesNotTouchTheDaemon | stricter: every systemctl call except `show` must be exactly `daemon-reload` |
| 11 | converted: a second run changes nothing and reloads nothing | internal/backend/tacacs: TestUnitsConvertedSecondRunChangesNothing | |
| 12 | converted: a reload that never happened is caught by asking systemd | internal/backend/tacacs: TestUnitsConvertedReloadThatNeverHappened | |
| 13 | interrupted: after the import, before any file was replaced | internal/backend/tacacs: TestUnitsInterruptedAfterTheImport | |
| 14 | interrupted: the new unit files are in place, the hand-managed drop-in still there | internal/backend/tacacs: TestUnitsInterruptedUnitFilesInPlace | |
| 15 | interrupted: both drop-ins exist (the rendered one was written, the old one not yet retired) | internal/backend/tacacs: TestUnitsInterruptedBothDropIns | |
| 16 | interrupted: a run that died leaves copies behind; the next run removes them | internal/backend/tacacs: TestUnitsInterruptedCopiesLeftBehind | |
| 17 | failure: a drop-in line tacctl did not write stops the conversion, by line | internal/backend/tacacs: TestUnitsFailureForeignDropInLine | settings_test.go TestConversionRefusesForeignLines covers the same refusal for a settings command |
| 18 | failure: a value the schema refuses stops the conversion | internal/backend/tacacs: TestUnitsFailureValueTheSchemaRefuses | |
| 19 | failure: a listener model that cannot be served stops before any file is replaced | internal/backend/tacacs: TestUnitsFailureListenerModelThatCannotBeServed | |
| 20 | failure: an error after files were replaced puts every one of them back | internal/backend/tacacs: TestUnitsFailureAfterFilesWereReplaced | the fault is injected through `life.commitUnits` instead of overriding rendered_record |
| 21 | failure: a tacctl.yaml that does not parse is not written into | internal/backend/tacacs: TestUnitsFailureUnparsableTacctlYAML | |
| 22 | failure: shipped unit files that are missing stop it before anything is read | internal/backend/tacacs: TestUnitsFailureShippedUnitFilesMissing | |
| 23 | upgrade: a conversion is reported, counted, and followed by one restart | internal/backend/tacacs: TestUpgradeUnitsConversionReportedCountedRestartedOnce | |
| 24 | upgrade: an install that is already converted is 'Unchanged' and is not restarted | internal/backend/tacacs: TestUpgradeUnitsAlreadyConvertedIsNotRestarted | |
| 25 | upgrade: other files updated (README, logrotate, templates) do not restart an unchanged unit | internal/backend/tacacs: TestUpgradeOtherFilesDoNotRestart | |
| 26 | upgrade: a re-rendered config restarts an unchanged unit | internal/backend/tacacs: TestUpgradeReRenderedConfigRestartsAnUnchangedUnit | |
| 27 | upgrade: a unit that will not start gets the old unit, drop-in and settings back, and is restarted on them | internal/backend/tacacs: TestUpgradeUnitThatWillNotStartIsRolledBack | |
| 28 | upgrade: when even the old files do not start it, that is said and nothing is half-converted | internal/backend/tacacs: TestUpgradeUnitRollbackThatFailsToo | |
| 29 | upgrade: a stopped conversion does not fail the upgrade and is in the summary | internal/backend/tacacs: TestUpgradeStoppedConversionDoesNotFailTheUpgrade | |
| 30 | not converted: readers show the drop-in; user mutations leave it alone and render no second one | internal/backend/tacacs: TestNotConvertedUserMutationLeavesTheDropIn | `user disable alice` is replaced by a no-op StoreApply with render. The effect (tree unchanged, no drop-in, nothing recorded) is asserted |
| 31 | not converted: the first settings change converts, keeping the other settings | internal/backend/tacacs: TestFirstSettingsChangeConverts (settings_test.go) + internal/backend/tacacs: TestFirstSettingsChangeConvertsThenUnitsInstallHasNothingToImport | was PARTIAL, completed in WP4.1 (internal/backend/tacacs: TestFirstSettingsChangeConvertsThenUnitsInstallHasNothingToImport): the last step is missing. The bats ran `units_install` afterwards and asserted no "settings moved" and level still 30 |
| 32 | not converted: a settings change whose unit does not come up puts the drop-in back | internal/backend/tacacs: TestConversionPutBackWhenTheUnitDoesNotComeUp (settings_test.go) | |
| 33 | uninstall: the layout from before the listener model is removed | internal/backend/tacacs: TestUninstallTheLayoutFromBeforeTheListenerModel | |
| 34 | uninstall: unit, template, instances, their drop-ins and enablement links are removed | internal/backend/tacacs: TestUninstallUnitsInstancesDropInsAndLinks | |
| 35 | uninstall: nothing installed is not an error | internal/backend/tacacs: TestUninstallNothingInstalledIsNotAnError | |

### tests/integration/upgrade_restart.bats (20 deleted tests)

The bats setup ran one upgrade with both backends enabled. The Go TACACS+ tests (lifecycle_upgrade_test.go) run only the tacacs module. The RADIUS tests (internal/backend/radius lifecycle_test.go) run only the radius module. The orchestrator tests (internal/lifecycle) use stand-in backends. No Go test runs one upgrade with both real backends, so "X only" is never asserted across backends. The isolation follows from the structure: each module's finish/config phase restarts only its own unit.

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | nothing new: a second upgrade restarts, starts, stops and reloads no service | internal/backend/tacacs: TestUpgradeNothingNewRestartsNothing + internal/backend/radius: TestUpgradeNothingToDo | radius side checks restarts=0 only (no daemon-reload count) |
| 2 | nothing new: the upgrade says so (no restart line, no file updated, no RADIUS summary) | internal/backend/tacacs: TestUpgradeNothingNewSaysSo + internal/backend/radius: TestUpgradeNothingToDo + internal/lifecycle: TestUpgradeOrderAndSummary | "0 file(s) updated." is in the second run of TestUpgradeOrderAndSummary, the empty RADIUS notes in TestUpgradeNothingToDo, the head in TestUpgradeNothingNewSaysSo |
| 3 | a new tacquito binary restarts tacquito only | internal/backend/tacacs: TestUpgradeNewBinaryRestartsTacquito | "only" relative to freeradius not exercised (see the heading) |
| 4 | a binary built by the run before a self-update's re-exec restarts tacquito, and is then the one kept | internal/backend/tacacs: TestUpgradeBinaryBuiltBeforeTheReExecIsRestartedAndKept | |
| 5 | the run before the re-exec hands over the commit it started from, for the summary | internal/backend/tacacs: TestUpgradeTheRunBeforeTheReExecHandsOverItsStart + internal/lifecycle: TestUpgradeHandoverAcrossTheReexec | the env var `TACCTL_UPGRADE_TACQUITO_FROM` reaching SetUpgradeFrom is in the lifecycle test |
| 6 | a rebuild after the re-exec (a new patch) keeps the .bak of the binary the daemon still runs, to go back to | internal/backend/tacacs: TestUpgradeRebuildAfterTheReExecKeepsTheRunningBak | |
| 7 | a restart that fails with an exit status still gets the rollback, and the upgrade says so | internal/backend/tacacs: TestUpgradeFailedRestartStillRollsBack | |
| 8 | a binary rolled back after a failed restart keeps its mode | internal/backend/tacacs: TestUpgradeBuildFailureRestoresThePreviousBinary (lifecycle_install_test.go) + internal/backend/tacacs: TestUpgradeFailedRestartRollbackKeepsTheBinaryMode | was PARTIAL, completed in WP4.1 (internal/backend/tacacs: TestUpgradeFailedRestartRollbackKeepsTheBinaryMode): 0755 under umask 077 is asserted on the build-failure restore. The failed-restart rollback uses the same copyPreserve backup and moveBack, but no test asserts its mode |
| 9 | a rollback restart that fails with an exit status ends in its error message | internal/backend/tacacs: TestUpgradeFailedRollbackRestartEndsInItsMessage | |
| 10 | a changed unit file restarts tacquito only | internal/backend/tacacs: TestUpgradeChangedUnitFileRestartsTacquito | "only": see the heading |
| 11 | a changed tacquito drop-in restarts tacquito only | internal/backend/tacacs: TestUpgradeChangedDropInRestartsTacquito | "only": see the heading |
| 12 | a changed tacquito.yaml render restarts tacquito only | internal/backend/tacacs: TestUpgradeChangedConfigRenderRestartsTacquito | "only": see the heading |
| 13 | a changed RADIUS render restarts FreeRADIUS only | internal/backend/radius: TestUpgradeFromBeforeTheDictionary | the trigger is the pre-dictionary state (artifacts re-rendered), not one older-rendered users file. It asserts "RADIUS: re-rendered" and exactly one freeradius restart. tacquito not restarted: see the heading |
| 14 | a changed RADIUS drop-in restarts FreeRADIUS only | internal/backend/radius: TestUpgradeDropinOnly | |
| 15 | changes for both backends restart each once | internal/backend/tacacs: TestUpgradeChangedConfigRenderRestartsTacquito + internal/backend/radius: TestUpgradeFromBeforeTheDictionary + internal/lifecycle: TestUpgradeOrderAndSummary | PARTIAL: each module restarts once on its own and the phase order is pinned. No test has both backends changed in one upgrade, so the bats check of exactly two restarts (freeradius then tacquito) is missing |
| 16 | a new README, logrotate file, completion or template restarts nothing; a customised template is named in the summary | internal/backend/tacacs: TestUpgradeNewReadmeOrLogrotateRestartsNothing + internal/lifecycle: TestUpgradeOrderAndSummary + internal/lifecycle: TestTemplatesSyncCustomisedAndRecorded | README/logrotate: no restart. Completion "Updated", "Customised template kept:" and the "Templates: kept 1 customised …" line are in the order test. The combined "4 file(s) updated." is not asserted as such |
| 17 | upgrade --branch to a branch whose lib/ differs re-executes the new tacctl once; that run has nothing more to pull | internal/lifecycle: TestMatrixSelfUpdateReexecs + internal/lifecycle: TestUpgradeHandoverAcrossTheReexec + internal/lifecycle: TestMatrixReexecGuard + internal/lifecycle: TestUpgradeBranchSwitchReportsAndReexecsOnce | was PARTIAL, completed in WP4.1 (internal/lifecycle: TestUpgradeBranchSwitchReportsAndReexecsOnce): --branch rebuilds and execs once, the guard stops a second exec, and the new process finishes. "Switched to branch 'x'." and "Management scripts updated: <sha>" are not asserted by any lifecycle test |
| 18 | upgrade --branch to a branch with the same bin/ and lib/ does not re-execute | DROP: the Go upgrade rebuilds and re-executes whenever the installed binary is not built from HEAD (plan §5.2 "Go-side self-update"); pinned by internal/lifecycle: TestUpgradeAReadmeOnlyPullStillRebuildsBecauseTheBinaryIsNotHEAD, TestUpgradeAfterConfigBranch | 0.1.18 re-executed only when bin/ or lib/ changed. Proposed as a §3.9 item (see the decisions section). |
| 19 | a pull on the same branch that changes lib/ re-executes once; one that changes only README.md does not | internal/lifecycle: TestMatrixSelfUpdateReexecs + internal/lifecycle: TestUpgradeAReadmeOnlyPullStillRebuildsBecauseTheBinaryIsNotHEAD (+ existing TestMatrixSelfUpdateReexecs for the first half) | was PARTIAL, completed in WP4.1 (internal/lifecycle: TestUpgradeAReadmeOnlyPullStillRebuildsBecauseTheBinaryIsNotHEAD (+ existing TestMatrixSelfUpdateReexecs for the first half)): only the first half (pull, build, exec once). The README-only "no re-exec" half is UNMAPPED, for the reason in row 18 The README-only half differs by design (see #18). |
| 20 | a tacquito build before a branch switch's re-exec is restarted on once, by the re-executed run | internal/backend/tacacs: TestUpgradeBuildBeforeTheReExecIsRestartedOnceByTheNewProcess + internal/lifecycle: TestUpgradeHandoverAcrossTheReexec | |

### tests/integration/listeners.bats (6 deleted tests)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | drop-in: a listener's own metrics_address is rendered; the default listener's is refused for it | internal/render/tacacs: TestDropInMetricsAddressOfAnInstance + internal/backend/tacacs: TestRenderOfAListenerModelThatCannotBeServed | the bats also checked that the refused render left the instance drop-in at 9100. The general "a refused render changes nothing" is in the second test (a TLS listener, not this case) |
| 2 | render: the drop-in is an artifact of the backend, staged and recorded with tacquito.yaml | internal/backend/tacacs: TestConfigRenderRendersConfigAndDropIn | the Artifacts() order [config, drop-in] is not asserted for this fixture (TestServiceListenerAddressesItsUnit pins index 2). "config validate: up to date" = RenderCheck Current |
| 3 | render: a hand-edited drop-in is reported as drift, never refuses a command, and is replaced with a copy kept | internal/backend/tacacs: TestHandEditedDropInIsDriftAndIsReplaced + internal/backend: TestDriftSelectionsAndHints | the status DRIFT hint text for a drop-in (and its lack of "store import --replace") is in TestDriftSelectionsAndHints. "Never refuses" = RenderGate OK |
| 4 | listeners verb: list, show, set and reset | internal/backend/tacacs: TestListenersVerb + internal/backend/tacacs: TestListenersList | the initial "default tcp :49" is in TestListenersList. `listeners frobnicate` → exit 2 has no Go counterpart: it was bash string dispatch (backend_call), and Go uses a typed interface |
| 5 | service verb: an optional listener addresses its unit; none is the whole backend | internal/backend/tacacs: TestServiceListenerAddressesItsUnit | |
| 6 | last login and 'log accounting' read every listener's accounting log | internal/backend/tacacs: TestLastLogin (tacacs_test.go) + internal/backend/tacacs: TestAccounting (log_test.go) | |

### tests/integration/radius.bats (2 deleted tests)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | last login: the newest Access-Accept of exactly that user; a longer name ending the same does not count | internal/backend/radius: TestLastLogin (status_test.go) | same planted log (the `user=alice bob` reject). Set.LastLogin covers backends_last_login |
| 2 | uninstall: a machine that merely has the FreeRADIUS package is not touched | internal/backend/radius: TestUninstallPackageOnly | asserts `set.Present()` == [tacacs] (backends_select_present), Installed()=false, and a quiet data phase |

### tests/integration/backup.bats (5 deleted tests)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | snapshot: nothing is added while the files equal the newest snapshot | internal/snapshot: TestSnapshotNothingIsAddedWhileTheFilesEqualTheNewest | named test exists and covers it (plus a tacctl.yaml-removed case) |
| 2 | snapshot: one command with several store writes takes one snapshot | internal/backend: TestStoreApplyTakesOneSnapshotForSeveralStoreWrites | named test exists and covers it |
| 3 | backup restore: a render that fails partway puts all four files back | internal/cli: TestBackupRestoreACommitThatFailsPutsEveryFileBack | named test exists (backup_knobs_test.go, `-tags testknobs`, TACCTL_FAULT=render-commit:tacacs). It asserts liveState unchanged and no .restore.* leftovers |
| 4 | backup restore: a failing writer also puts the files back | internal/cli: TestBackupRestoreAWriterThatFailsPutsEveryFileBack + internal/backend: TestApplyForcedRendersWithForceAndKeepsNothingOnSuccess + internal/backend: TestStoreApplyAFailingWriterPutsBothFilesBackAndReturnsItsError | the named test exists, but its writer fails on the first replace (store.yaml.tacctl-new is a directory), so nothing is half-written. Rolling back a half-written store is in TestApplyForced… (writer writes store.yaml, then fails). Rolling back both files (store + tacctl.yaml) is in the StoreApply test |
| 5 | backup restore --legacy: a failing render after the import puts everything back | internal/cli: TestBackupRestoreLegacyARenderThatFailsPutsEveryFileBack | named test exists (`-tags testknobs`, TACCTL_FAULT=render-stage:tacacs) |

### tests/integration/scope_protocols.bats (2 deleted tests)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | scope protocols: the store's own schema refuses an unknown protocol | internal/store: TestScopeSetProtocols + internal/store: TestValidateProtocols | the comment says only "internal/store". Exact tests: the writer refuses `protocols=ldap` (TestScopeSetProtocols, no message check). The message "protocols must be a list drawn from: tacacs, radius" is in TestValidateProtocols |
| 2 | scope protocols: mutating it is superuser-only under the tier gate | internal/tier: TestPermitsMatchesBash | testdata/permits.psv row `scope|protocols|0|0|1|1|0` (readonly, operator refused; superuser permitted) |

### tests/integration/store_cli.bats (1 deleted test)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | store: tier gate keeps store commands superuser-only | internal/tier: TestPermitsMatchesBash + internal/tier: TestGateAndSudoersAgree | both named tests exist. permits.psv rows `store|show` and `store|import` = 0,0,1. TestGateAndSudoersAgree asserts store show reaches no lower tier |

### tests/integration/store_mutations.bats (2 deleted tests)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | the one-prefix-one-scope rule: past the command's own check, the store writer refuses too | internal/store: TestScopeSetOnePrefixOneScope | the comment says only "internal/store"; this is the exact test. It asserts "prefix 10.10.99.0/24 is claimed by scopes" (validate.go appends "(one scope per prefix)"). The scope not being created follows from Mutate failing atomically, but is not asserted |
| 2 | hashes and secrets do not reach any process's argv | DROP: bash-specific: python3 argv check (Go: exec recorder test internal/cli: TestSecretsNeverOnArgv) | the Go test exists (scope_test.go): the same commands plus `scope secret generate`, every recorded argv checked for the 5 needles |

### tests/integration/tiers.bats (2 deleted tests)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | tier: store show never reaches the read-only tier, in the gate or in sudoers | internal/tier: TestGateAndSudoersAgree | the named test exists; its last check is exactly this (sudoers text has no "store", and the gate refuses readonly and operator) |
| 2 | tier gate and sudoers rules agree on every verb, for each lower tier | internal/tier: TestGateAndSudoersAgree | named test exists, over the same verb list, including the sudoers-only reverse check |

### tests/integration/characterisation.bats (1 deleted test)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | hash generate: without python3-bcrypt it says so and points at 'hash commands' | DROP: §3.9 item 4 | item 4: "Preflight no longer runs `python3 -c "import bcrypt"`". Already removed from the working-tree file |

### tests/integration/config_templates.bats (1 deleted test)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | config wti: falls back to the inline walkthrough when no template resolves | DROP: embedded templates: alt-dir template fallback | the plan's dropped list (go-rewrite.md §2.3, line 157) names config_templates.bats:257-275. Templates are embedded: internal/assets TestTemplatesAreTheTreesFiles (every config/templates file embedded byte for byte, wti and wti-radius included). internal/devices TestResolveTemplate (built-in without an override dir, `Origin()` "built-in cisco.template", override wins) |

### tests/integration/config_radius.bats (1 deleted test)

| # | bats test | replaced by | note |
|---|---|---|---|
| 1 | config cisco\|juniper --protocol radius: without any template file the built-in text renders the same config | DROP: embedded templates: alt-dir template fallback | the plan names config_radius.bats:571-587. Same Go evidence: internal/assets TestTemplatesAreTheTreesFiles (cisco-radius, juniper-radius embedded), internal/devices TestResolveTemplate, and internal/devices TestRenderGoldens (output from the embedded templates against the goldens) |

