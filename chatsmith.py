import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.exceptions import InvalidSignature
import logging
import requests
import random
import os
from datetime import datetime

class RSAEncryption:
    def __init__(self):
        self.TEXT_TYPE_RSA = "RSA"
        self.TEXT_TYPE_RSA_ECB_PKCS1Padding = "RSA/ECB/PKCS1Padding"
        self.public_key = None

    def get_public_key(self):
        """
        Converts the hardcoded base64 public key string to a cryptography PublicKey object
        Returns: PublicKey object or None if conversion fails
        """
        try:
            # Hardcoded public key from the original Java code
            self.public_key = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCB8knKtJGP5VAkVhKvAtOQhl1ERGCv+jLVGDd9yAbnuJQwcb7y8AMmr4AZ8VONJh73epzsqg9vRgmToztXvzZPsj83AAGuCZIFWQb+QLl93VSuDk9a+uC+4E483XMtRD9YQoyXfusIGJbiyPNJqaY1i5SgZwzu7VYPpcSn7lv4eQIDAQAB"
            key_bytes = self.public_key.encode('utf-8')
            der_key_bytes = base64.b64decode(key_bytes)
            public_key_obj = load_der_public_key(der_key_bytes)
            return public_key_obj

        except Exception as e:
            logging.error(f"Error loading public key: {e}")
            return None

    def encrypt(self, cipher_text):
        """
        Encrypts the given text using RSA encryption with PKCS1v15 padding
        Args:
            cipher_text (str): Text to encrypt
        Returns:
            str: Base64 encoded encrypted text, or error message
        """
        try:
            public_key = self.get_public_key()

            if public_key is None:
                return "NO_PUB_KEY"

            text_bytes = cipher_text.encode('utf-8')

            encrypted_bytes = public_key.encrypt(
                text_bytes,
                padding.PKCS1v15()
            )

            encrypted_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')

            return encrypted_b64

        except Exception as e:
            logging.error(f"Encryption error: {e}")
            return "NO_ENCRYPT"


class ChatSmithAIModel:
    def __init__(
        self,
        provider="openai",
        model_name="gpt-4o-mini",
        system_prompt="",
        device_id=None,
        access_token=None,
        messages=None
    ):
        self.provider = provider
        self.model_name = model_name
        self.user_id = os.urandom(8).hex()
        self.system_prompt = system_prompt
        self.device_id = device_id or self.generate_device_id()
        self.rsa_encryption = RSAEncryption()
        self.access_token = access_token
        if not messages:
            if system_prompt:
                self.messages = [{"role": "system", "content": system_prompt}]
            else:
                self.messages = []
        else:
            self.messages = messages
        self.session = requests.Session()
        self._logger = logging.getLogger("ChatSmithAIModel")

    def generate_device_id(self):
        return os.urandom(8).hex().upper()

    def fetch_access_token(self):
        url = 'https://api.vulcanlabs.co/smith-auth/api/v1/token'
        resp = self.session.post(
            url,
            headers={
                'accept': 'application/json',
                # 'accept-encoding': 'gzip',
                'connection': 'Keep-Alive',
                'content-type': 'application/json; charset=utf-8',
                'host': 'api.vulcanlabs.co',
                'user-agent': 'Chat Smith Android, Version 3.9.27(949)',
                'x-vulcan-application-id': 'com.smartwidgetlabs.chatgpt',
                'x-vulcan-request-id': str(random.randint(10**20, 10**21)),
            },
            json={
                'device_id': self.device_id,
                'order_id': '',
                'product_id': '',
                'purchase_token': '',
                'subscription_id': '',
            }
        )
        resp.raise_for_status()
        data = resp.json()
        self.access_token = data.get("AccessToken")
        return self.access_token

    def _generate_headers_chat(self, ts):
        headers = {
            'accept': 'application/json',
            # 'accept-encoding': 'gzip',
            'authorization': f'Bearer {self.access_token}',
            'connection': 'Keep-Alive',
            'content-type': 'application/json; charset=utf-8',
            'host': 'api.vulcanlabs.co',
            'user-agent': 'Chat Smith Android, Version 3.9.27(949)',
            'x-auth-token': self.rsa_encryption.encrypt(
                '{"androidId":"%s","exp":%d,"iat":%d,"sha1":"lnVkAT9EQQjq8x+YzyKHXs9Otd8="}' % (self.device_id, ts, ts)
            ),
            'x-firebase-appcheck-error': '-9%3A+Integrity+API+error+%28-9%29%3A+Binding+to+the+service+in+the+Play+Store+has+failed.+This+can+be+due+to+having+an+old+Play+Store+version+installed+on+the+device.%0AAsk+the+user+to+update+Play+Store.%0A+%28https%3A%2F%2Fdeveloper.android.com%2Freference%2Fcom%2Fgoogle%2Fandroid%2Fplay%2Fcore%2Fintegrity%2Fmodel%2FIntegrityErrorCode.html%23CANNOT_BIND_TO_SERVICE%29.',
            'x-vulcan-application-id': 'com.smartwidgetlabs.chatgpt',
            'x-vulcan-request-id': str(random.randint(10**20, 10**21)),
        }
        return headers

    def _generate_chat_payload(self, user_message, nsfw_check=True, tools=None):
        tools = tools if tools is not None else [{"function": {"name": "create_ai_art"}}]
        self.messages.append({"role": "user", "content": user_message})
        return {
            'usage_model': {
                'provider': self.provider,
                'model': self.model_name,
            },
            'user': self.user_id,
            'messages': self.messages,
            'nsfw_check': nsfw_check,
            'tools': tools,
        }

    def get_ai_response(self, user_message, nsfw_check=True, tools=None):
        if not self.access_token:
            self.fetch_access_token()
        ts = int(datetime.now().timestamp())
        payload = self._generate_chat_payload(user_message, nsfw_check=nsfw_check, tools=tools)

        url = 'https://api.vulcanlabs.co/smith-v2/api/v7/chat_android'
        resp = self.session.post(
            url,
            headers={
                'accept': 'application/json',
                # 'accept-encoding': 'gzip',
                'authorization': f'Bearer {self.access_token}',
                'connection': 'Keep-Alive',
                'content-type': 'application/json; charset=utf-8',
                'host': 'api.vulcanlabs.co',
                'user-agent': 'Chat Smith Android, Version 3.9.27(949)',
                'x-auth-token': self.rsa_encryption.encrypt(
                    '{"androidId":"%s","exp":%d,"iat":%d,"sha1":"lnVkAT9EQQjq8x+YzyKHXs9Otd8="}' % (self.device_id, ts, ts)
                ),
                'x-firebase-appcheck-error': '-9%3A+Integrity+API+error+%28-9%29%3A+Binding+to+the+service+in+the+Play+Store+has+failed.+This+can+be+due+to+having+an+old+Play+Store+version+installed+on+the+device.%0AAsk+the+user+to+update+Play+Store.%0A+%28https%3A%2F%2Fdeveloper.android.com%2Freference%2Fcom%2Fgoogle%2Fandroid%2Fplay%2Fcore%2Fintegrity%2Fmodel%2FIntegrityErrorCode.html%23CANNOT_BIND_TO_SERVICE%29.',
                'x-vulcan-application-id': 'com.smartwidgetlabs.chatgpt',
                'x-vulcan-request-id': str(random.randint(10**20, 10**21)),
            },
            json=payload
        )
        resp.raise_for_status()
        self.messages.append(resp.json()["choices"][0]["Message"])
        return resp

    def ask(self, message):
        response = self.get_ai_response(message)
        if response.status_code == 200:
            return response
        else:
            self._logger.error("AI response error: %s", response.status_code)
            return None
    def interactive(self):
        while True:
            user_input = input("> ")
            response = self.ask(user_input)
            print(f"AI: {response.json()['choices'][0]['Message']['content']}")
if __name__ == "__main__":
    ai_model = ChatSmithAIModel()
    ai_model.interactive()
