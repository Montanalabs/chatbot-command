#! Chatbot command parser — untrusted a chat message can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires runChat — the chatbot command parser sink
#! @effect io
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant runChat

type BotCmd = HelpC | StatusC | ResetC
type Decision = ChatCmd(BotCmd) | IgnoreChat

let raw = fetch<web>  # UNTRUSTED a chat message — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
using runChat { privileged { runChat(d) } }  # act on the trusted decision only
