# Taintwatch

Runtime information-flow control for LLM agents. Every piece of data carries an
integrity and confidentiality label plus a provenance trail. Tool calls are
checked against a declarative policy, so untrusted text (a web page, an inbound
email) cannot silently steer shell commands or leak secrets.

Status: early research prototype.
