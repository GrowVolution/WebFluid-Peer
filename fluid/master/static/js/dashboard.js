(function () {
    "use strict"

    const form = document.getElementById("search")
    if (!form) return
    const input = document.getElementById("q")
    const inactive = document.getElementById("inactive")
    const rows = document.getElementById("rows")
    const empty = document.getElementById("empty")
    const summary = document.getElementById("summary")
    const stale = document.getElementById("stale")
    const prev = document.getElementById("prev")
    const next = document.getElementById("next")
    const REFRESH = 15000
    const SIZE = 25
    const t = (key, values) => window.wfNet ? window.wfNet.t(key, values) : key

    const params = new URLSearchParams(location.search)
    const state = { query: params.get("q") || "", page: Math.max(1, Number(params.get("page")) || 1),
                    inactive: params.get("inactive") === "1", pages: 1, last: null, sequence: 0 }

    function cell(content) {
        const node = document.createElement("td")
        if (content instanceof Node) node.append(content)
        else node.textContent = content ?? "–"
        return node
    }

    function render(data) {
        const fragment = document.createDocumentFragment()
        for (const item of data.items) {
            const row = document.createElement("tr")
            const link = document.createElement("a")
            link.href = `/apps/${encodeURIComponent(item.app)}`
            link.textContent = item.app
            row.append(cell(link), cell(item.origin), cell(item.name), cell(t(item.active ? "NET_ACTIVE" : "NET_INACTIVE")),
                       cell(item.last_seen), cell(item.head ? String(item.head.seq) : "–"))
            fragment.append(row)
        }
        rows.replaceChildren(fragment)
        empty.hidden = data.items.length > 0
        state.pages = data.pages
        summary.textContent = `${t("NET_DASH_RESULTS", { total: data.total, page: data.page, pages: data.pages })} · ${t("NET_DASH_UPDATED", { time: new Date().toLocaleTimeString() })}`
        prev.disabled = state.page <= 1
        next.disabled = state.page >= data.pages
        stale.hidden = true
    }

    async function load() {
        const sequence = ++state.sequence
        const query = new URLSearchParams({ page: String(state.page), size: String(SIZE) })
        if (state.query) query.set("q", state.query)
        if (state.inactive) query.set("inactive", "1")
        try {
            const response = await fetch(`/api/v1/apps?${query}`, { cache: "no-store", credentials: "omit" })
            if (!response.ok) throw new Error(`HTTP_${response.status}`)
            const data = await response.json()
            if (sequence !== state.sequence) return
            state.last = new Date()
            render(data)
        } catch (error) {
            if (sequence !== state.sequence) return
            stale.hidden = false
            stale.textContent = t("NET_DASH_STALE", { error: error.message || "UNREACHABLE",
                time: state.last ? state.last.toLocaleTimeString() : "–" })
        }
    }

    function remember() {
        const query = new URLSearchParams()
        if (state.query) query.set("q", state.query)
        if (state.page > 1) query.set("page", String(state.page))
        if (state.inactive) query.set("inactive", "1")
        history.replaceState(null, "", query.toString() ? `/?${query}` : "/")
    }

    let timer = null
    input.addEventListener("input", () => {
        clearTimeout(timer)
        timer = setTimeout(() => {
            state.query = input.value.trim().slice(0, 64)
            state.page = 1
            remember()
            load()
        }, 250)
    })
    inactive.addEventListener("change", () => {
        state.inactive = inactive.checked
        state.page = 1
        remember()
        load()
    })
    form.addEventListener("submit", event => {
        event.preventDefault()
        state.query = input.value.trim().slice(0, 64)
        state.page = 1
        remember()
        load()
    })
    prev.addEventListener("click", () => {
        if (state.page <= 1) return
        state.page -= 1
        remember()
        load()
    })
    next.addEventListener("click", () => {
        if (state.page >= state.pages) return
        state.page += 1
        remember()
        load()
    })
    input.value = state.query
    inactive.checked = state.inactive
    load()
    setInterval(() => { if (!document.hidden) load() }, REFRESH)
})()
