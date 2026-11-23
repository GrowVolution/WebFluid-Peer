(function () {
    "use strict"

    const root = document.documentElement
    const button = document.getElementById("theme")
    if (!button) return

    const preference = window.matchMedia("(prefers-color-scheme: dark)")
    let chosen = null

    function sync() {
        const dark = chosen ?? preference.matches
        root.dataset.theme = dark ? "dark" : "light"
        button.setAttribute("aria-pressed", String(dark))
    }

    button.addEventListener("click", () => {
        chosen = root.dataset.theme !== "dark"
        sync()
    })
    preference.addEventListener("change", sync)
    sync()

    window.wfNet = {
        texts: (() => {
            try { return JSON.parse(document.getElementById("net-texts")?.textContent || "{}") }
            catch { return {} }
        })(),
        t(key, values) {
            let text = this.texts[key] ?? key
            for (const [name, value] of Object.entries(values || {})) text = text.replace(`%(${name})s`, String(value))
            return text
        }
    }
})()
