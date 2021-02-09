const json2md = require("json2md")

console.log(json2md([
    { h1: "Hunting Rules" }
  , { blockquote: "T1105 - Ingress Tool Transfer - Certutil" }
  , { img: [
        { title: "Metsys", source: "https://www.metsys.fr/wp-content/themes/metsys/images/svg/metsys-logo.svg" }
      ]
    }
  , { h2: "Hunt Tags" }
  , { ul: [
        {bold: 'ID:'}
      , "You can programmatically generate Markdown content"
      , "..."
      ]
    }
  , { h2: "How to contribute" }
  , { ol: [
        "Fork the project"
      , "Create your branch"
      , "Raise a pull request"
      ]
    }
  , { h2: "Code blocks" }
  , { p: "Below you can see a code block example." }
  , { "code": {
        language: "js"
      , content: [
          "function sum (a, b) {"
        , "   return a + b"
        , "}"
        , "sum(1, 2)"
        ]
      }
    }
]))