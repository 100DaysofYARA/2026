rule BlueDelta_Initial_Webhook_Stage3 {
    meta:
        desc = "Detects initial webhook used by BlueDelta credential harvesting campaign"
        author = "@josh_penny"
        reference = "https://www.recordedfuture.com/research/gru-linked-bluedelta-evolves-credential-harvesting"
        severity = "Medium"
        date = "2026-01-12"
    strings:
        // Commonly used url domain includes webhook.site. 2 second redirect to benign .pdf
        $wait = "<meta http-equiv=\"refresh\" content=\"2;" nocase
        $pdf = /<object\s+data="https:\/\/.*\.pdf"/ nocase
    condition:
        $wait and $pdf
}
rule BlueDelta_Hidden_Form_Element_Stage4 {
    meta:
        desc = "Detects hidden HTML form element using the page URL at page load for BlueDelta credential harvesting campaign"
        author = "@josh_penny"
        reference = "https://www.recordedfuture.com/research/gru-linked-bluedelta-evolves-credential-harvesting"
        severity = "High"
        date = "2026-01-12"
    strings:
        $hidden = "<input type=\"hidden\" id=\"href\" role=\"textbox\"" nocase
        $labelledby = "aria-labelledby=\"userNameLabel\"" nocase
    condition:
        $hidden and $labelledby
}
rule BlueDelta_JS_Beacon_Stage5 {
    meta:
        desc = "Detects JavaScript used to capture the current URL, set a hidden form element, send a “page-opened” beacon, and change the displayed URL in the victim's browser"
        author = "@josh_penny"
        reference = "https://www.recordedfuture.com/research/gru-linked-bluedelta-evolves-credential-harvesting"
        severity = "High"
        date = "2026-01-12"
    strings:
        $urlParams = "const urlParams" nocase
        $user = "const user = urlParams.get('u');" nocase
        $xhr_var = "var xhr" nocase
        $xhr_send = "\"page_opened\": user}));" nocase
        $owa = "'/owa/'" nocase
        $pdf_viewer = "/pdfviewer?pdf=browser" nocase
    condition:
        3 of ($urlParams, $user, $xhr_var, $xhr_send) and ($owa or $pdf_viewer)
}
rule BlueDelta_MyFunction_Stage6 {
    meta:
        desc = "Detects MyFunction JavaScript function used to exfiltrate credentials in BlueDelta credential harvesting campaign"
        author = "@josh_penny"
        reference = "https://www.recordedfuture.com/research/gru-linked-bluedelta-evolves-credential-harvesting"
        severity = "Critical"
        date = "2026-01-12"
    strings:
        $user = "username" nocase
        $user_hidden = "usernamehidden" nocase
        $oldPwd = "oldPwd" nocase
        $password = "password" nocase
        $post = "POST" 
    condition:
        ($user and $oldPwd and $post) or ($user_hidden and $password and $post) // Match on either new or older HTML variant
}
rule BlueDelta_Credential_Harvesting_Stages_3_6 {
    meta:
        desc = "A rule to detect Stages: 3, 4, 5, and 6 of the BlueDelta credential harvesting campaign: Initial Webhook, Hidden Form Element, JS Beacon, and MyFunction. Captures legacy HTML content pattern."
        author = "@josh_penny"
        reference = "https://www.recordedfuture.com/research/gru-linked-bluedelta-evolves-credential-harvesting"
        severity = "Critical"
        date = "2026-01-12"
    condition:
        any of (BlueDelta_Initial_Webhook_Stage3, BlueDelta_Hidden_Form_Element_Stage4, BlueDelta_JS_Beacon_Stage5, BlueDelta_MyFunction_Stage6)
}