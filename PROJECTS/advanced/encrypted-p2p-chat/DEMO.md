<!-- ©AngelaMos | 2026 -->
<!-- DEMO.md -->

<div align="center">

```ruby
███████╗███╗   ██╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗███████╗██████╗
██╔════╝████╗  ██║██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗
█████╗  ██╔██╗ ██║██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   █████╗  ██║  ██║
██╔══╝  ██║╚██╗██║██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██╔══╝  ██║  ██║
███████╗██║ ╚████║╚██████╗██║  ██║   ██║   ██║        ██║   ███████╗██████╔╝
╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   ╚══════╝╚═════╝
```

**Demo & Preview**

<br>

<a href="https://chat.carterperez-dev.com">
  <img src="https://img.shields.io/badge/▶_TRY_IT_LIVE-chat.carterperez--dev.com-DC143C?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Live Demo"/>
</a>

<br>

```ruby
docker compose up -d    →    https://localhost
```

<br>

[Register](#register) · [Login](#login) · [New Conversation](#new-conversation) · [Empty Conversation](#empty-conversation) · [First Message](#first-message) · [Encrypted Messaging](#encrypted-messaging) · [Mobile View](#mobile-view)

</div>

---

### Register

Passwordless account creation with WebAuthn passkey enrollment — username and display name are the only fields, no password is ever entered or stored

![Register](assets/images/register.png)

---

### Login

Passkey authentication with optional username field — leave blank to use a discoverable credential resolved by the authenticator

![Login](assets/images/login.png)

---

### New Conversation

Username search resolves the recipient's identity key from the directory before any message is composed

![New Conversation](assets/images/new-conversation.png)

---

### Empty Conversation

Fresh thread with E2EE badge and presence indicator — no plaintext history is ever stored on the server, so a new conversation truly starts empty

![Empty Conversation](assets/images/empty-conversation.png)

---

### First Message

Outbound message encrypted client-side with the recipient's public key and pushed over WebSocket — the server only ever sees ciphertext

![First Message](assets/images/first-message.png)

---

### Encrypted Messaging

Live two-way conversation with delivery timestamps and the lock indicator on every bubble confirming end-to-end encryption per message

![Encrypted Messaging](assets/images/chat.png)

---

### Mobile View

Responsive single-pane layout with collapsible sidebar — passkey auth and E2EE work identically on mobile via the platform authenticator

![Mobile View](assets/images/mobile.png)
