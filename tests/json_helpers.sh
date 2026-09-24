# Shell JSON accessors — tests are shell-only; the Python that remains
# is legacy to migrate off, not a pattern to copy.
#
# These exist because most suites reached for python3 to do one thing: pull a field out of
# a console API response. That cost every one of them a `SKIP: python3 not available`
# branch, and a suite that skips is a suite that is not testing anything.
#
# Scope, deliberately: flat objects and arrays of flat objects, which is what the console
# API returns. This is NOT a JSON parser and must not grow into one — if an assertion needs
# real nested traversal, assert on the wire bytes instead, which is closer to what the
# client actually sees.
#
#   json_str  '<json>' <key>              -> the string value, escapes intact
#   json_num  '<json>' <key>              -> the number/bool value (unquoted)
#   json_pem  '<json>' <key> <outfile>    -> decoded (\n -> newline) into a file
#   json_obj  '<json>' <key> <value>      -> the one array element whose <key> is <value>
#   json_has  '<json>' <key> <value>      -> yes|no, is there such an element
#
# `json_str` is whitespace-tolerant after the colon: the ACME server emits compact JSON,
# the console pretty-prints, and a helper that only handled one of them is how you get an
# assertion that silently reads the empty string and passes.

# The string value of <key>. Escapes are returned as they appear on the wire.
json_str() {
    printf '%s' "$1" | tr -d '\n' \
        | sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1
}

# The unquoted value of <key> (number, true/false, null).
json_num() {
    printf '%s' "$1" | tr -d '\n' \
        | sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*\([-0-9a-zA-Z.]*\).*/\1/p' | head -1
}

# Decode a JSON string field into a file. PEM arrives with literal \n two-character
# sequences; printf %b turns them back into newlines and is POSIX, unlike `sed 's/\\n/\n/'`
# whose replacement-side \n is a GNU extension (§3d: the suites run on macOS too).
json_pem() {
    # A PEM field normally ends with a literal \n; decoding that AND appending one leaves a
    # trailing blank line, which breaks any assertion that reads `tail -1`. Drop the encoded
    # one and let printf supply the single real newline.
    _jp=$(json_str "$1" "$2")
    printf '%b\n' "${_jp%\\n}" > "$3"
}

# One element of a top-level array of flat objects, selected by <key>=<value>.
# Splits on the },{ boundary; flat objects only, by the scope note above.
json_obj() {
    printf '%s' "$1" | tr -d '\n' | sed -e 's/^[[:space:]]*\[//' -e 's/\][[:space:]]*$//' \
        | sed 's/}[[:space:]]*,[[:space:]]*{/}\
{/g' | grep -F "\"$2\":\"$3\"" | head -1
}

# Is there an array element whose <key> equals <value>?
json_has() {
    if [ -n "$(json_obj "$1" "$2" "$3")" ]; then echo yes; else echo no; fi
}

# Split a top-level JSON array into one element per line, brace-depth aware so an element
# containing a nested array or object survives intact. This is the one concession to
# nesting in this file: json_obj's naive },{ split cannot handle a profile whose
# custom_extensions is itself an array of objects. It is still not a parser -- it does no
# unescaping and understands no types -- it only finds element boundaries, which is what
# the assertions need to scope a grep to the right record.
json_elems() {
    printf '%s' "$1" | awk '
        { line = line $0 }
        END {
            n = length(line); depth = 0; instr = 0; esc = 0; start = 0
            for (i = 1; i <= n; i++) {
                c = substr(line, i, 1)
                if (esc)          { esc = 0; continue }
                if (c == "\\")    { esc = 1; continue }
                if (c == "\"")    { instr = !instr; continue }
                if (instr)        continue
                if      (c == "{") { if (depth == 1) start = i; depth++ }
                else if (c == "}") { depth--; if (depth == 1) print substr(line, start, i - start + 1) }
                else if (c == "[") depth++
                else if (c == "]") depth--
            }
        }'
}

# The one element of a top-level array whose <key> is <value>, nesting-safe.
json_rec() { json_elems "$1" | grep -F "\"$2\":\"$3\"" | head -1; }
