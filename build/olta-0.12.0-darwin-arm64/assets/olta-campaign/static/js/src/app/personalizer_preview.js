(function () {
    "use strict"

    var previewTimer = null

    function editorHTML() {
        if (window.CKEDITOR && CKEDITOR.instances["html_editor"]) {
            return CKEDITOR.instances["html_editor"].getData()
        }
        return $("#html_editor").val() || ""
    }

    function previewContext() {
        return {
            FirstName: $("#preview-first-name").val() || "Ada",
            LastName: "Lovelace",
            Position: "Engineer",
            Department: $("#preview-department").val() || "Engineering",
            Company: $("#preview-company").val() || "Olta",
            ManagerName: "Grace Hopper",
            PhishingURL: $("#bitb-preview-url").val() || "https://login.example.test/",
            Language: "en"
        }
    }

    function evaluateVariations() {
        var payload = {
            subject: $("#subject").val() || "",
            text: $("#text_editor").val() || "",
            html: editorHTML(),
            context: previewContext()
        }
        $("#personalizer-preview-status").text("Generating five variations...")
        query("/v1/personalizer/preview", "POST", payload, true)
            .success(function (data) {
                var container = $("#personalizer-variations").empty()
                $.each(data.variations, function (index, variation) {
                    var item = $("<div>").addClass("list-group-item")
                    $("<h5>").addClass("list-group-item-heading").text((index + 1) + ". " + (variation.subject || "(No subject)")).appendTo(item)
                    $("<pre>").css({"background": "transparent", "border": 0, "padding": 0, "white-space": "pre-wrap"}).text(variation.text || variation.html || "(No body)").appendTo(item)
                    container.append(item)
                })
                $("#personalizer-preview-status").text("Five independently randomized previews.")
            })
            .error(function (data) {
                var message = data.responseJSON && data.responseJSON.message ? data.responseJSON.message : "Preview failed"
                $("#personalizer-preview-status").text(message)
            })
    }

    function updateBITBPreview() {
        var content = editorHTML()
        if (!content) {
            content = '<div style="font:14px system-ui;padding:36px"><h2>Sign in</h2><p>Preview login content</p><input style="display:block;margin:12px 0;padding:10px;width:100%" placeholder="Email"><button style="padding:10px 18px">Continue</button></div>'
        }
        var payload = {
            url: $("#bitb-preview-url").val(),
            title: "Sign in",
            theme: $("#bitb-preview-theme").val(),
            content: content
        }
        $("#bitb-preview-status").text("Rendering " + payload.theme + "...")
        query("/v1/bitb/preview", "POST", payload, true)
            .success(function (data) {
                var documentHTML = '<!doctype html><html><head><meta charset="utf-8"><style>html,body{height:100%;margin:0;overflow:hidden}.olta-bitb{position:absolute}</style></head><body>' + data.html + '</body></html>'
                $("#bitb-preview-frame").prop("srcdoc", documentHTML).show()
                $("#bitb-preview-status").text("Showing " + data.theme + " at " + data.url)
            })
            .error(function (data) {
                var message = data.responseJSON && data.responseJSON.message ? data.responseJSON.message : "BITB preview failed"
                $("#bitb-preview-status").text(message)
            })
    }

    function schedulePreview() {
        clearTimeout(previewTimer)
        previewTimer = setTimeout(evaluateVariations, 350)
    }

    function bindEditor() {
        var editor = window.CKEDITOR && CKEDITOR.instances["html_editor"]
        if (editor && !editor.oltaPreviewBound) {
            editor.oltaPreviewBound = true
            editor.on("change", schedulePreview)
        }
    }

    $(document).ready(function () {
        $("#evaluate-variations").on("click", evaluateVariations)
        $("#refresh-bitb-preview").on("click", updateBITBPreview)
        $("#bitb-preview-theme").on("change", updateBITBPreview)
        $("#subject, #text_editor, #preview-first-name, #preview-department, #preview-company").on("input", schedulePreview)
        $("#modal").on("shown.bs.modal", function () {
            bindEditor()
            schedulePreview()
        }).on("hidden.bs.modal", function () {
            $("#personalizer-variations").empty()
            $("#bitb-preview-frame").hide().prop("srcdoc", "")
        })
    })
}())
