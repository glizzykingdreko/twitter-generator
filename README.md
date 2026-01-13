# Twitter / X Headers Generator

![Twitter headers](./images/headers.png)
<div align="center">
  <img src="https://img.shields.io/badge/Status-Complete-brightgreen" alt="Status: Complete">
  <img src="https://img.shields.io/badge/Type-Research-blue" alt="Type: Research">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License: MIT">
  <a href="https://github.com/GlizzyKingDreko/twitter_generator"><img src="https://img.shields.io/github/stars/GlizzyKingDreko/twitter_generator?style=flat-square&logo=github" alt="GitHub stars"></a>
  <a href="https://github.com/GlizzyKingDreko/twitter_generator"><img src="https://img.shields.io/badge/GitHub-Repo-black?logo=github&style=flat-square" alt="GitHub repo"></a>
</div>

<br>

<div align="center">
  <a href="https://github.com/GlizzyKingDreko/twitter_generator-python"><img src="https://img.shields.io/badge/Check%20the%20Python%20version-purple?logo=python&style=flat-square" alt="Check the Python version"></a>
  <a href="https://medium.com/@glizzykingdreko/x-former-twitter-login-flow-reconstruction-episode-1-headers-generation-68a23add39e1"><img src="https://img.shields.io/badge/Read%20the%20full%20article%20on%20Medium-12100E?logo=medium&logoColor=white&style=flat-square" alt="Read the full article on Medium"></a>
  <a href="https://buymeacoffee.com/glizzykingdreko"><img src="https://img.shields.io/badge/Support%20my%20research%20by%20buying%20me%20a%20coffee-242424?style=flat-square&logo=buy-me-a-coffee&logoColor=yellow" alt="Buy me a coffee"></a>
</div>


Python module with an attached reverse-engineering study of the X (former Twitter) `x-client-transaction-id` and `x-xp-forwarded-for` request headers.

## Series Context

This repository represents **Episode 1** of a multi-part analysis of Twitter/X login-flow protections.

Be sure to follow me on [Medium](https://medium.com/@glizzykingdreko) and [Github](https://github.com/GlizzyKingDreko) in order to prevent loosing next episodes.

Next one is going to be about the first antibot challenge.

## Learning 
Be sure to check out [LEARN.md](./LEARN.md) in order to understand how this has been made as well as the [full article on Medium](https://www.com)

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
  - [X-Client-Transaction-Id](#x-client-transaction-id)
  - [X-XP-Forwarded-For](#x-xp-forwarded-for)
- [Learning](#learning)
- [Multi-Language Implementations](#step-10-multi-language-implementations)
- [Author](#author)


---

## Installation

```bash
pip install twitter-generator
```

Or from source:

```bash
git clone https://github.com/GlizzyKingDreko/twitter-generator.git
cd twitter-generator
pip install -e .
```


## Quick Start

### X-Client-Transaction-Id

```python
from twitter_generator import ClientTransactionGenerator

generator = ClientTransactionGenerator(
    ondemand_file=ondemand_js_content, # Dynamic js file content
    home_page=home_page_html # Loaded homepage content
)

transaction_id = generator.generate(
    "GET", # Method you are going to use
    "/api/1.1/statuses/user_timeline.json" # Route of the request
)

print(transaction_id)
```


### X-XP-Forwarded-For

```python
from twitter_generator import XPForwardedForGenerator

generator = XPForwardedForGenerator(
    guest_id="v1%3A176824413470818950" # Your guest_id cookie
)

env = {
    'userAgent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
    'hasBeenActive': False,
    'webdriver': False
}

token = generator.generate(env)
print(token)


# Or decrypting it via
generator.decode(
    token, 
    generator._derive_key_from_guest_id(guest_id)
)
```


## API Reference

### ClientTransactionGenerator

```python
class ClientTransactionGenerator:
    def __init__(self, ondemand_file: str, home_page: str)
    def generate(self, method: str, path: str) -> str
```


### XPForwardedForGenerator

```python
class XPForwardedForGenerator:
    def __init__(self, guest_id: Optional[str] = None)
    def generate(self, env: Dict) -> str
    def decode(self, token: str, key: Optional[bytes] = None) -> Dict
    def decode_with_key(self, token: str, key_hex: str) -> Dict
    def decode_with_guest_id(self, token: str, guest_id: str) -> Dict

    @staticmethod
    def extract_guest_id_from_cookie(
        cookie_string: str
    ) -> Optional[str]
```


## Implementations in Other Languages

Be sure to check the
- [GO Version](./xp_forwarded_for/go/main.go)
- [NodeJS Version](./xp_forwarded_for/nodejs/index.js)

## License

MIT License.
See [LICENSE](LICENSE) for details.

---


## Author

If you found this project helpful or interesting, consider starring the repo and following me for more security research and tools, or buy me a coffee to keep me up.

<p align="center">
  <a href="https://github.com/GlizzyKingDreko"><img src="https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white" alt="GitHub"></a>
  <a href="https://twitter.com/GlizzyKingDreko"><img src="https://img.shields.io/badge/Twitter-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white" alt="Twitter"></a>
  <a href="https://medium.com/@GlizzyKingDreko"><img src="https://img.shields.io/badge/Medium-12100E?style=for-the-badge&logo=medium&logoColor=white" alt="Medium"></a>
  <a href="https://discord.com/users/GlizzyKingDreko"><img src="https://img.shields.io/badge/Discord-7289DA?style=for-the-badge&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="mailto:glizzykingdreko@protonmail.com"><img src="https://img.shields.io/badge/ProtonMail-8B89CC?style=for-the-badge&logo=protonmail&logoColor=white" alt="Email"></a>
  <a href="https://buymeacoffee.com/glizzykingdreko"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-yellow?style=for-the-badge&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>

