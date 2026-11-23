(function () {
    "use strict"

    const detail = document.getElementById("detail")
    if (!detail || !detail.dataset.app) return
    const REFRESH = 30000

    async function refresh() {
        if (document.hidden || detail.contains(document.activeElement)) return
        try {
            const response = await fetch(location.pathname, { cache: "no-store", credentials: "omit" })
            if (!response.ok) return
            const page = new DOMParser().parseFromString(await response.text(), "text/html")
            const fresh = page.getElementById("detail")
            if (fresh) detail.replaceChildren(...fresh.childNodes)
        } catch {}
    }

    setInterval(refresh, REFRESH)
})()
