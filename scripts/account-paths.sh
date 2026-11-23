# Prints each account's path (/Users/<name>) that the files under a folder hold, once each,
# for make release, which refuses an app that holds a person's.
#
# A program's instructions are not read. A compiler stores a short string inside them, in
# pieces, so the bytes of "/Users/S" can stand in front of an instruction whose own bytes
# would be read as the rest of a name. A string that is stored whole lies outside them: what
# is left out is each section the program marks as holding instructions only.
set -eu
if [ $# -ne 1 ] || [ ! -d "$1" ]; then
  echo "usage: sh scripts/account-paths.sh <folder>" >&2
  exit 2
fi
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

# A file's bytes; a program's are each architecture's in turn, without those sections.
contents() {
  archs=$(lipo -archs "$1" 2>/dev/null) || { cat "$1"; return; }
  for arch in $archs; do
    slice=$1
    case $archs in
    *" "*)
      slice=$scratch/slice
      lipo "$1" -thin "$arch" -output "$slice"
      ;;
    esac
    # otool lists a section's size, in hex, and its offset in the file, then its flags, whose
    # highest bit marks instructions only. A listing it cannot be read from leaves nothing
    # out, and neither does an archive's, whose offsets are counted from each member.
    otool -l "$slice" | awk '
      NR == 1 && /^Archive/ { exit }
      $1 == "sectname" { section = 1 }
      section && $1 == "size" { size = $2 }
      section && $1 == "offset" { offset = $2 }
      section && $1 == "flags" {
        if (length($2) == 10 && $2 ~ /^0x[89a-f]/) print offset, size
        section = 0
      }
    ' | sort -n | {
      at=0
      while read -r offset size; do
        # A line end between the parts, so the bytes on either side form no path together.
        # Two such sections can lie end to end, and head refuses a count of 0.
        if [ $((offset - at)) -gt 0 ]; then
          tail -c +$((at + 1)) "$slice" | head -c $((offset - at))
        fi
        echo
        at=$((offset + size))
      done
      tail -c +$((at + 1)) "$slice"
    }
  done
}

find "$1" -type f > "$scratch/files"
while IFS= read -r file; do
  contents "$file"
  echo
done < "$scratch/files" > "$scratch/bytes"
grep -aoE '/Users/[A-Za-z0-9._-]+' "$scratch/bytes" | sort -u
