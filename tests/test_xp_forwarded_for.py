from twitter_generator import XPForwardedForGenerator

if __name__ == "__main__":
    guest_id = 'v1%3A176824413470818950'
    env = {
        'userAgent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
        'hasBeenActive': False,
        'webdriver': False
    }

    # Generate a token with the guest_id
    generator = XPForwardedForGenerator(guest_id)
    generated = generator.generate(env)
    print(generated)

    # Decrypt the generated token with the guest_id
    print(generator.decode(generated, generator._derive_key_from_guest_id(guest_id)))

    # Decrypt a real token from a request header
    browser_token = '973f0757e7cff62a248a1171e41070db1b0fbb7256a49323f86a9f96f3f4ecb5e4f85ed5e308d9e3f5f7480c0c139c3560dc2fa6ac71827a3124cb324bdbcd3c2a013392e5634018749fa1bc84a7458880cc333f3897af514fb1cc4a29c580cea44a9607b2d2c348b8c863c26aa8232e69ee1fbc4470d195b6ed705ce03e2ddc2a97b3dfa4846f9c037c8113c71439ae09a299e3bff9624c93b4455a1e7d10e14cf958b9b972f0042189d19bb25f455308992cffe00d1cc4a0a930ed409e35ec74541e2ac54c38162d646f3a64f2253578fca73a5e196f8c33d1b22c3297b44f74add1a8f123e60422bd294757da2d53d2fcfb0a19e5ca5b5e98f63d1b25f4cbc2'
    print(generator.decode(browser_token, generator._derive_key_from_guest_id(guest_id)))