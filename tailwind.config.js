/** @type {import('tailwindcss').Config} */
let colors = require("tailwindcss/colors")
module.exports = {
    content: ["./templates/**/*.{html,js}"],
    theme: {
        extend: {
            colors: {
                neutral: colors.slate,
                positive: colors.green,
                urge: colors.violet,
                warning: colors.yellow,
                info: colors.blue,
                critical: colors.red,
            }
        },
    },
    plugins: [
        require("a17t")
    ],
}