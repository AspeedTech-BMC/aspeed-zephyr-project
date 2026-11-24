#!/usr/bin/env bash
# Copyright (c) 2026 ASPEED Technology Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Bring the mainline branch up to the latest aspeed-dev and vendor Zephyr:
#   0. fetch both and back up the branch
#   1. rebase onto aspeed-dev
#   2. merge the vendor changes into the module's driver copies (sync_vendor.py)
#   3. report the vendor changes the sync does not carry over by itself
#
# The script stops where a person has to decide (a rebase or merge conflict)
# and prints what to do. Run it again afterwards; finished steps are skipped.
#
# aspeed_base records the aspeed-dev commit the *_mainline board files were
# last checked against, as vendor_base does for the driver copies. Step 1
# lists the aspeed-dev changes to the board files since then, whoever did the
# rebase, and a finished run records the new aspeed-dev there.
#
# Usage: mainline/scripts/update.sh [options]
#   --vendor DIR       vendor Zephyr repository (default: ../zephyr next to
#                      this repository)
#   --aspeed REF       aspeed-dev to rebase onto (default: origin/aspeed-dev)
#   --vendor-ref REF   vendor commit to sync to (default:
#                      gerrit/aspeed-dev-v3.7.0)
#   --no-fetch         use the refs as they are
#   --dry-run          only report what steps 1 and 2 would do
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
MODULE=$(git -C "$HERE" rev-parse --show-toplevel)
MAINLINE=$(cd "$HERE/.." && pwd)
VENDOR=$(cd "$MODULE/.." && pwd)/zephyr
ASPEED_REF=origin/aspeed-dev
VENDOR_REF=gerrit/aspeed-dev-v3.7.0
FETCH=1
DRY=0

while [ $# -gt 0 ]; do
	case $1 in
	--vendor) VENDOR=$2; shift 2 ;;
	--aspeed) ASPEED_REF=$2; shift 2 ;;
	--vendor-ref) VENDOR_REF=$2; shift 2 ;;
	--no-fetch) FETCH=0; shift ;;
	--dry-run) DRY=1; shift ;;
	-h|--help) sed -n "4,27p" "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "unknown option $1" >&2; exit 2 ;;
	esac
done

cd "$MODULE"
GITDIR=$(git rev-parse --git-dir)
STATE=$GITDIR/mainline-update
SYNC=$HERE/sync_vendor.py
BRANCH=$(git rev-parse --abbrev-ref HEAD)

say() { printf '\n== %s\n' "$*"; }
stop() { printf '\nSTOP: %s\n' "$*"; exit 2; }

# A rebase or a sync left half done has to be finished first.
if [ -d "$GITDIR/rebase-merge" ] || [ -d "$GITDIR/rebase-apply" ]; then
	git diff --name-only --diff-filter=U | sed 's/^/  conflict: /'
	stop "a rebase is in progress. Resolve the files above (see the hints in
the previous run), 'git add' them, 'git rebase --continue', then run this
script again."
fi
marked=$(cd "$MAINLINE" && awk 'NR > 1 { print $1 }' "$HERE/vendor_map.txt" |
	xargs -r grep -l '^<<<<<<< module' 2>/dev/null | sed 's|^|mainline/|' || true)
if [ -n "$marked" ]; then
	printf '%s\n' "$marked" | sed 's/^/  conflict: /'
	stop "merge conflicts left in the files above. Resolve them, then run
  python3 $SYNC $VENDOR $VENDOR_REF --set-base
and this script again."
fi

# Step 0
say "0. fetch and back up"
if [ $FETCH = 1 ]; then
	git fetch -q "${ASPEED_REF%%/*}" "${ASPEED_REF#*/}"
	git -C "$VENDOR" fetch -q "${VENDOR_REF%%/*}" "${VENDOR_REF#*/}"
fi
TARGET=$(git -C "$VENDOR" rev-parse "$VENDOR_REF")
BASE=$(cat "$HERE/vendor_base")
# The vendor base before this update, kept across reruns for the step 3 report.
if [ -f "$STATE" ] && grep -q "^TARGET=$TARGET$" "$STATE"; then
	OLD_BASE=$(sed -n 's/^OLD_BASE=//p' "$STATE")
else
	OLD_BASE=$BASE
	[ $DRY = 0 ] && printf 'OLD_BASE=%s\nTARGET=%s\n' "$OLD_BASE" "$TARGET" > "$STATE"
fi
echo "branch $BRANCH at $(git rev-parse --short HEAD)"
echo "aspeed-dev: $(git rev-list --count HEAD.."$ASPEED_REF") new commit(s) on $ASPEED_REF"
echo "vendor:     $(git -C "$VENDOR" rev-list --count "$OLD_BASE".."$TARGET") new commit(s), ${OLD_BASE:0:12} -> ${TARGET:0:12}"

# Step 1
say "1. rebase onto $ASPEED_REF"
# The aspeed-dev commit the *_mainline board files were last checked
# against. aspeed_base records it; without that file it is the aspeed-dev
# base of the newest earlier position of the branch (its reflog) that had a
# different base, which is where the branch stood before the last rebase.
ABASE_FILE=$HERE/aspeed_base
if [ -f "$ABASE_FILE" ]; then
	OLD_HEAD_BASE=$(cat "$ABASE_FILE")
	ABASE_FROM=aspeed_base
else
	cur_mb=$(git merge-base HEAD "$ASPEED_REF")
	OLD_HEAD_BASE=$cur_mb
	ABASE_FROM="merge base (no aspeed_base, no earlier base in the reflog)"
	for c in $(git reflog --format=%H "refs/heads/$BRANCH" 2>/dev/null | head -100); do
		mb=$(git merge-base "$c" "$ASPEED_REF" 2>/dev/null) || continue
		if [ "$mb" != "$cur_mb" ]; then
			OLD_HEAD_BASE=$mb
			ABASE_FROM="reflog of $BRANCH"
			break
		fi
	done
fi
if git merge-base --is-ancestor "$ASPEED_REF" HEAD; then
	echo "already on $ASPEED_REF"
else
	ours=$(git diff --name-only "$(git merge-base HEAD "$ASPEED_REF")" HEAD | sort)
	theirs=$(git diff --name-only HEAD..."$ASPEED_REF" | sort)
	overlap=$(comm -12 <(echo "$ours") <(echo "$theirs"))
	if [ $DRY = 1 ]; then
		echo "files changed on both sides (possible conflicts):"
		printf '%s\n' "${overlap:-  none}" | sed 's/^/  /'
	else
		[ -z "$(git status --porcelain --untracked-files=no)" ] ||
			stop "the working tree has uncommitted changes; commit or remove them first."
		backup=backup-$BRANCH-$(date +%Y%m%d-%H%M)
		git branch "$backup" HEAD
		echo "backup: $backup"
		if ! git rebase "$ASPEED_REF"; then
			git diff --name-only --diff-filter=U | sed 's/^/  conflict: /'
			cat <<'EOF'

How to resolve, by file:
  apps/mcu-runtime/soc/ast2700/mmc.c keep the aspeed-dev changes and the
                                     <aspeed/mmc.h> include for mainline
  a commit whose change aspeed-dev already has: take the aspeed-dev side;
  the commit becomes empty and is dropped
EOF
			stop "rebase conflict. Resolve, 'git add', 'git rebase --continue', then run
this script again."
		fi
	fi
fi
echo "aspeed-dev changes to the board files the *_mainline copies may need too"
echo "(${OLD_HEAD_BASE:0:12}..$ASPEED_REF, base from $ABASE_FROM):"
board=$(git diff --stat "$OLD_HEAD_BASE" "$ASPEED_REF" -- \
	'apps/mcu-runtime/boards/ast2700_evb_ast2700_bootmcu.conf' \
	'apps/mcu-runtime/boards/ast2700_evb_ast2700_bootmcu.overlay' 'apps/mcu-runtime/prj.conf' |
	sed '$d')
if [ -n "$board" ]; then
	printf '%s\n' "$board" | sed 's/^/  /'
	echo "  see: git diff ${OLD_HEAD_BASE:0:12} $ASPEED_REF -- apps/mcu-runtime/boards apps/mcu-runtime/prj.conf"
else
	echo "  none"
fi
echo "app files the mainline branch changes:"
git diff --stat "$(git merge-base HEAD "$ASPEED_REF")" HEAD -- apps | sed 's/^/  /'

# Step 2
say "2. sync the vendor driver copies to ${TARGET:0:12}"
if [ "$BASE" = "$TARGET" ]; then
	echo "vendor_base is already ${TARGET:0:12}"
elif [ $DRY = 1 ]; then
	python3 "$SYNC" "$VENDOR" "$TARGET" --dry-run | sed 's/^/  /'
else
	if ! python3 "$SYNC" "$VENDOR" "$TARGET"; then
		cat <<'EOF'

How to resolve: keep the module's own edits and take the vendor logic.
The module's edits are:
  - names kept apart from upstream: aspeed_otp_driver_api, aspeed_jesd216_*,
    Kconfig symbols ending in _ASPEED
  - calls that replace the vendor core API patches: ipm_bootmcu_*(),
    spi_aspeed_nor_get_ops()
  - upstream API forms: DEVICE_API(), sdhc_host_props fields, "peripheral"
EOF
		stop "sync conflict. Resolve the CONFLICT files, then run
  python3 $SYNC $VENDOR $TARGET --set-base
and this script again."
	fi
fi

# Step 3
say "3. vendor changes ${OLD_BASE:0:12}..${TARGET:0:12} the sync does not carry over"
report() {
	local title=$1; shift
	local out
	out=$(git -C "$VENDOR" diff --stat=120 "$OLD_BASE" "$TARGET" -- "$@" | sed '$d')
	echo "-- $title"
	if [ -n "$out" ]; then echo "$out"; else echo "   none"; fi
}
report "Kconfig and CMake of driver classes (new drivers, new options; mirror in mainline/drivers/<class>/)" \
	'drivers/*/Kconfig*' 'drivers/*/CMakeLists.txt' 'drivers/misc/aspeed/Kconfig' \
	'drivers/misc/aspeed/CMakeLists.txt'
report "bindings and SoC devicetree (new required properties; mirror in mainline/dts/riscv/aspeed/ast27xx_bootmcu_app.dtsi)" \
	'dts/bindings' 'dts/riscv/aspeed'
report "AST2700 EVB board (default Kconfig values; mirror as Kconfig defaults or in the app *_mainline.conf)" \
	'boards/aspeed/ast2700_evb'
report "Zephyr core headers the vendor tree patches (need a module-side replacement)" \
	'include/zephyr/drivers/ipm.h' 'include/zephyr/drivers/spi.h' \
	'include/zephyr/drivers/flash.h' 'include/zephyr/drivers/mbox.h'

echo "-- vendor headers the app includes that the module does not provide (add with --add)"
missing=0
while read -r inc; do
	if [ ! -e "$MAINLINE/include/$inc" ] && git -C "$VENDOR" cat-file -e "$TARGET:include/$inc" 2>/dev/null; then
		echo "   $inc"
		missing=1
	fi
done < <(grep -rhoE '#include <zephyr/(drivers/misc/aspeed/[a-z0-9_]+|drivers/cptra|crypto/(ecdsa|lms)[a-z_]*)\.h>' \
	"$MODULE/apps/mcu-runtime" | sed -E 's/#include <(.*)>/\1/' | sort -u)
[ $missing = 1 ] || echo "   none"

say "next"
if [ $DRY = 1 ]; then
	echo "dry run only: nothing was rebased or merged."
else
	# The board files are now checked against this aspeed-dev.
	git rev-parse "$ASPEED_REF" > "$ABASE_FILE"
	echo "review 'git status' and 'git diff', mirror what steps 1 and 3 list into the"
	echo "*_mainline board files and the module, then commit the sync together with"
	echo "mainline/scripts/aspeed_base as: zephyr: sync the vendor drivers to ${TARGET:0:11}"
	echo "then build against Zephyr main and run the boot test on the board."
	rm -f "$STATE"
fi
