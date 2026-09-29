-- docs/publish.lua — rewrite the guides' cross-links for the published site.
--
-- ⚠️ WITHOUT THIS EVERY CROSS-GUIDE LINK IS A 404. The guides link to each other the way a
-- reader of the repository needs them to: `[deployment](deployment.md)`. Published, each
-- guide becomes a DIRECTORY of per-chapter pages, so `deployment.md` names nothing that
-- exists. There are 132 such links; none of them would work.
--
-- A published guide becomes `../<name>/index.html` — one level up because every chapter page
-- of the linking guide sits inside its own directory.
--
-- ⚠️ architecture.md IS NOT PUBLISHED, and nine links point at it. It is the design record,
-- written for whoever is changing the code rather than for an operator, so it stays in the
-- repository — which means a link to it has to leave the site rather than dangle. Those
-- become the file on GitHub, anchors and all, which is where it actually is.
--
-- The exclusion list is not a second copy of publish.sh's: the script passes it in, so the
-- two cannot disagree about what is published.

local site_root = os.getenv("FASTPKI_DOCS_SOURCE_URL")
    or "https://github.com/fastpki/fastpki/blob/main/docs/"

-- Guides the script is NOT publishing, as a set. Passed in as a space-separated list so this
-- filter never has to be edited when the set changes.
local unpublished = {}
for name in (os.getenv("FASTPKI_DOCS_UNPUBLISHED") or "architecture.md"):gmatch("%S+") do
    unpublished[name] = true
end

-- The repository root on GitHub, for the files that are not published as pages.
local repo_root = site_root:gsub("docs/$", "")

-- ⚠️ THE PDF CANNOT SET PICTOGRAPHS, AND THE FAILURE IS THE WHOLE DOCUMENT. The guides use a
-- handful of symbols that no ordinary text font carries — the camera on every screenshot
-- placeholder, the console's own button glyphs — and xelatex stops on the first one it
-- cannot set rather than dropping it, so one character costs the entire PDF:
--
--     ! LaTeX Error: Unicode character ☀ (U+2600) not set up for use with LaTeX.
--
-- They become words for the PDF only. The HTML keeps them, because a browser has fonts for
-- all of this and the symbols are how the console labels those buttons. The variation
-- selector after ⚠ goes too: it asks for an emoji rendering that a text font cannot give.
-- ⚠️ ONLY WHAT THE FONT GENUINELY CANNOT SET. publish.sh builds its PDF image with DejaVu,
-- which covers every symbol the guides use — the arrows, the box-drawing diagrams, ⚠, the
-- console's own button glyphs — so none of those is rewritten and the PDF reads like the
-- guide. What is left is the camera on a screenshot placeholder, which lives in the emoji
-- block that no text font carries, and the variation selector that asks for an emoji
-- rendering of the character before it.
--
-- Rewriting more than this was the first attempt, before the font was added, and it degraded
-- the PDF to work around a packaging gap: arrows became "->" and the corners of every diagram
-- became "+", so the diagrams stopped looking like diagrams. Substitute for what is missing,
-- not for what is inconvenient.
--
-- Code and CodeBlock are filtered as well as Str, because the diagrams live inside fenced
-- code blocks and a code block is not a Str.
local pdf_mode = os.getenv("FASTPKI_DOCS_PDF") == "1"
local ascii = {
    ["\u{FE0F}"]  = "",            -- emoji variation selector
    ["\u{1F4F7}"] = "Screenshot",  -- 📷, the only emoji in the guides
}

local function to_ascii(s)
    for from, to in pairs(ascii) do s = s:gsub(from, to) end
    return s
end

function Str(el)
    if not pdf_mode then return el end
    local s = to_ascii(el.text)
    if s ~= el.text then return pandoc.Str(s) end
    return el
end

function Code(el)
    if not pdf_mode then return el end
    el.text = to_ascii(el.text)
    return el
end

function CodeBlock(el)
    if not pdf_mode then return el end
    el.text = to_ascii(el.text)
    return el
end

function Link(el)
    -- ⚠️ A LINK OUT OF docs/ IS NOT A PAGE ON THE SITE. The guides point at files elsewhere
    -- in the repository — `../deploy/cloud/README.md` — and only the guides are published,
    -- so a relative path like that resolves to nothing. It becomes the file on GitHub, which
    -- is where a reader can actually read it. Handled before the sibling case because that
    -- one deliberately matches bare filenames only.
    local out, out_anchor = el.target:match("^%.%./(.+%.md)(#?[%w%-%.]*)$")
    if out then
        el.target = repo_root .. out .. out_anchor
        return el
    end

    -- Only relative links to a sibling guide. Anything absolute, or an in-page anchor, is
    -- already right and must be left alone.
    local file, anchor = el.target:match("^([%w%-]+%.md)(#?[%w%-%.]*)$")
    if not file then return el end

    if unpublished[file] then
        el.target = site_root .. file .. anchor
    else
        -- ⚠️ THE ANCHOR CANNOT SURVIVE, so it is dropped rather than carried to a page that
        -- does not have it. The target guide is split into chapter pages and pandoc decides
        -- which page a heading lands on, so `config-reference.md#some-heading` has no
        -- predictable published address. The index lists every chapter, which is a working
        -- link to the right guide instead of a broken one into it. Four links carry an
        -- anchor today and all four point at architecture.md, handled above.
        el.target = "../" .. file:gsub("%.md$", "") .. "/index.html"
    end
    return el
end
