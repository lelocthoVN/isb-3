import logging
import os
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


class GenerationKey:
    def __init__(self, symmetric_key_path: str, public_key_path: str, private_key_path: str) -> None:
        """
        :param symmetric_key_path: путь до симметричного ключа
        :param public_key_path: путь до открытого ключа
        :param private_key_path: путь до закрытого ключа
        """
        self.symmetric_key_path = symmetric_key_path
        self.public_key_path = public_key_path
        self.private_key_path = private_key_path

    def symmetric_key(self) -> bytes:
        """
        Генерирует случайный ключ.
        :return: bytes
        """
        key = os.urandom(16)
        logging.info("Symmetric text успешно сгенерирован!")
        return key

    def asymmetric_key(self) -> None:
        """
        Записывает по указанным путям в файлы сгенерированные асимметричные открытый и закрытый ключи.
        :return: None
        """
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        try:
            with open(self.public_key_path, 'wb') as public_out:
                public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.PublicFormat.SubjectPublicKeyInfo))
            logging.info(f'Открытый ключ успешно сгенерирован и записан в файл {self.public_key_path}')
        except OSError as err:
            logging.warning(f'{err} ошибка при записи в файл {self.public_key_path}')
        try:
            with open(self.private_key_path, 'wb') as private_out:
                private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                            encryption_algorithm=serialization.NoEncryption()))
                logging.info(f'Закрытый ключ успешно сгенерирован и записан в файл {self.private_key_path}')
        except OSError as err:
            logging.warning(f'{err} ошибка при записи в файл {self.private_key_path}')

    def symmetric_key_encryption(self) -> None:
        """
         Считывает из файла сгенерированный открытый ключ, шифрует его и
         записывает по указанному пути зашифрованный симметричный ключ.
        :return: None
        """
        try:
            with open(self.public_key_path, "rb") as pem_in:
                public_bytes = pem_in.read()
        except OSError as err:
            logging.warning(f'{err} ошибка при чтении из файла {self.public_key_path}')
        d_public_key = load_pem_public_key(public_bytes)
        key = self.symmetric_key()
        c_key = d_public_key.encrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                       algorithm=hashes.SHA256(), label=None))
        try:
            with open(self.symmetric_key_path, "wb") as f:
                f.write(c_key)
                logging.info(f'Симметричный ключ успешно сгенерирован и записан в файл {self.symmetric_key_path}')
        except OSError as err:
            logging.warning(f'{err} ошибка при записи в файл {self.symmetric_key_path}')
