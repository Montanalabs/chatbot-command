#! VULNERABLE chatbot-command — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant runChat

let raw = fetch<web>
using runChat { privileged { runChat(raw) } }  # tainted -> tool: REJECTED
